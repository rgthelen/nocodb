import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { extractRolesObj } from 'nocodb-sdk';
import * as ejs from 'ejs';
import { PresignedUrl } from 'src/models';
import type { AppConfig } from '~/interface/config';

import { UsersService } from '~/services/users/users.service';
import { AppHooksService } from '~/services/app-hooks/app-hooks.service';

import { GlobalGuard } from '~/guards/global/global.guard';
import { NcError } from '~/helpers/catchError';
import { Acl } from '~/middlewares/extract-ids/extract-ids.middleware';
import { MetaApiLimiterGuard } from '~/guards/meta-api-limiter.guard';
import { PublicApiLimiterGuard } from '~/guards/public-api-limiter.guard';
import { NcRequest } from '~/interface/config';

@Controller()
export class AuthController {
  constructor(
    protected readonly usersService: UsersService,
    protected readonly appHooksService: AppHooksService,
    protected readonly config: ConfigService<AppConfig>,
  ) {}

  @Post([
    '/auth/user/signup',
    '/api/v1/db/auth/user/signup',
    '/api/v1/auth/user/signup',
    '/api/v2/auth/user/signup',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async signup(@Req() req: NcRequest, @Res() res: Response): Promise<any> {
    if (this.config.get('auth', { infer: true }).disableEmailAuth) {
      NcError.forbidden('Email authentication is disabled');
    }
    res.json(
      await this.usersService.signup({
        body: req.body,
        req,
        res,
      }),
    );
  }

  @Post([
    '/auth/token/refresh',
    '/api/v1/db/auth/token/refresh',
    '/api/v1/auth/token/refresh',
    '/api/v2/auth/token/refresh',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async refreshToken(
    @Req() req: NcRequest,
    @Res() res: Response,
  ): Promise<any> {
    res.json(
      await this.usersService.refreshToken({
        body: req.body,
        req,
        res,
      }),
    );
  }

  @Post([
    '/auth/user/signin',
    '/api/v1/db/auth/user/signin',
    '/api/v1/auth/user/signin',
    '/api/v2/auth/user/signin',
  ])
  @UseGuards(PublicApiLimiterGuard, AuthGuard('local'))
  @HttpCode(200)
  async signin(@Req() req: NcRequest, @Res() res: Response) {
    if (this.config.get('auth', { infer: true }).disableEmailAuth) {
      NcError.forbidden('Email authentication is disabled');
    }
    await this.setRefreshToken({ req, res });
    res.json(await this.usersService.login(req.user, req));
  }

  @UseGuards(GlobalGuard)
  @Post(['/api/v1/auth/user/signout', '/api/v2/auth/user/signout'])
  @HttpCode(200)
  async signOut(@Req() req: NcRequest, @Res() res: Response): Promise<any> {
    if (!(req as any).isAuthenticated?.()) {
      NcError.forbidden('Not allowed');
    }
    res.json(
      await this.usersService.signOut({
        req,
        res,
      }),
    );
  }

  @Post(`/auth/google/genTokenByCode`)
  @HttpCode(200)
  @UseGuards(PublicApiLimiterGuard, AuthGuard('google'))
  async googleSignin(@Req() req: NcRequest, @Res() res: Response) {
    await this.setRefreshToken({ req, res });
    res.json(await this.usersService.login(req.user, req));
  }

  @Get('/auth/google')
  @UseGuards(PublicApiLimiterGuard, AuthGuard('google'))
  googleAuthenticate() {
    // google strategy will take care the request
  }

  @Get('/auth/oidc')
  @UseGuards(PublicApiLimiterGuard)
  oidcAuthenticate(@Req() req: NcRequest, @Res() res: Response) {
    // Direct implementation instead of using the OIDC strategy
    try {
      console.log('OIDC Auth - Initial request - Direct Implementation');
      
      // Generate the auth URL manually
      const authorizationURL = process.env.NC_OIDC_AUTHORIZATION_URL;
      const callbackURL = process.env.NC_OIDC_CALLBACK_URL || process.env.NC_REDIRECT_URL;
      const clientID = process.env.NC_OIDC_CLIENT_ID;
      const scope = process.env.NC_OIDC_SCOPE || 'openid profile email';
      
      // Generate a random state for security
      const state = Math.random().toString(36).substring(2);
      
      // Create the authorization URL
      const authUrl = `${authorizationURL}?` +
        `client_id=${encodeURIComponent(clientID)}` +
        `&redirect_uri=${encodeURIComponent(callbackURL)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scope)}` +
        `&state=${encodeURIComponent(state)}`;
      
      console.log('Redirecting to:', authUrl);
      
      // Redirect to Rownd auth URL
      return res.redirect(authUrl);
    } catch (error) {
      console.error('Error in OIDC auth redirect:', error);
      return res.redirect('/signin?error=auth_redirect_failed');
    }
  }

  @Get('/auth/oidc/callback')
  @UseGuards(PublicApiLimiterGuard)
  async oidcCallback(@Req() req: NcRequest, @Res() res: Response) {
    try {
      console.log('OIDC Callback Handler - Starting - Direct Implementation');
      
      // Get the code from the query parameters
      const code = req.query.code;
      if (!code) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('No authorization code provided');
              setTimeout(function() {
                window.location.href = '/signin?error=no_code';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>No authorization code was provided by the identity provider.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      // Exchange code for token
      const tokenURL = process.env.NC_OIDC_TOKEN_URL;
      const callbackURL = process.env.NC_OIDC_CALLBACK_URL || process.env.NC_REDIRECT_URL;
      const clientID = process.env.NC_OIDC_CLIENT_ID;
      const clientSecret = process.env.NC_OIDC_CLIENT_SECRET;
      
      console.log('Exchanging code for token');
      
      const tokenResponse = await fetch(tokenURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code as string,
          redirect_uri: callbackURL,
          client_id: clientID,
          client_secret: clientSecret,
        }).toString(),
      });
      
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        console.error('Token exchange failed:', errorText);
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('Failed to exchange code for token');
              setTimeout(function() {
                window.location.href = '/signin?error=token_exchange_failed';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>Failed to exchange authorization code for token.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      const tokenData = await tokenResponse.json();
      console.log('Token received with keys:', Object.keys(tokenData));
      
      if (!tokenData.access_token) {
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('No access token in response');
              setTimeout(function() {
                window.location.href = '/signin?error=no_access_token';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>No access token was provided by the identity provider.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      // Get user info
      const userInfoURL = process.env.NC_OIDC_USERINFO_URL;
      console.log('Fetching user info');
      
      const userInfoResponse = await fetch(userInfoURL, {
        headers: {
          'Authorization': `Bearer ${tokenData.access_token}`,
        },
      });
      
      if (!userInfoResponse.ok) {
        const errorText = await userInfoResponse.text();
        console.error('User info request failed:', errorText);
        return res.status(400).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('Failed to retrieve user info');
              setTimeout(function() {
                window.location.href = '/signin?error=user_info_failed';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>Failed to retrieve user information from the identity provider.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      const userInfo = await userInfoResponse.json();
      console.log('User info received with keys:', Object.keys(userInfo));
      
      // Extract email
      let email = userInfo.email;
      
      if (!email) {
        // Try to find any property that might contain an email
        for (const key in userInfo) {
          if (
            key.toLowerCase().includes('email') && 
            typeof userInfo[key] === 'string' &&
            userInfo[key].includes('@')
          ) {
            email = userInfo[key];
            break;
          }
        }
      }
      
      if (!email && userInfo.sub) {
        // Use sub as a fallback
        email = `${userInfo.sub}@rownd-user.nocodb.com`;
      } else if (!email) {
        // Generate a random email as last resort
        const uniqueId = Math.random().toString(36).substring(2);
        email = `rownd-user-${uniqueId}@nocodb.com`;
      }
      
      console.log('Using email:', email);
      
      // Find or create user
      const { User } = req.ncSiteUrl ? require('~/models') : require('../../../models');
      
      let user;
      try {
        user = await User.getByEmail(email);
        if (!user) {
          console.log('User not found, creating new user');
          user = await this.usersService.registerNewUserIfAllowed({
            email_verification_token: null,
            email,
            password: '',
            req,
          } as any);
        }
      } catch (error) {
        console.error('Error finding/creating user:', error);
        return res.status(500).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('Failed to find or create user');
              setTimeout(function() {
                window.location.href = '/signin?error=user_creation_failed';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>Failed to find or create user account.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      if (!user) {
        return res.status(500).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('No user object after creation');
              setTimeout(function() {
                window.location.href = '/signin?error=user_not_found';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>Could not find or create a user account.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      // Set user in the request and proceed with normal flow
      req.user = user;
      
      // Set refresh token
      try {
        await this.setRefreshToken({ req, res });
      } catch (error) {
        console.error('Error setting refresh token:', error);
      }
      
      // Generate JWT token
      let token;
      try {
        const loginResult = await this.usersService.login(user, req);
        token = loginResult.token;
      } catch (error) {
        console.error('Error generating login token:', error);
        return res.status(500).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Authentication Failed</title>
            <script>
              console.error('Failed to generate login token');
              setTimeout(function() {
                window.location.href = '/signin?error=token_generation_failed';
              }, 3000);
            </script>
          </head>
          <body>
            <h1>Authentication Failed</h1>
            <p>Failed to generate login token.</p>
            <p>Redirecting to sign in page...</p>
          </body>
          </html>
        `);
      }
      
      // Success! Return a page that sets the token and redirects
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authentication Successful</title>
          <script>
            try {
              localStorage.setItem('nc_token', '${token}');
              console.log('Token stored successfully');
              window.location.href = '/';
            } catch (error) {
              console.error('Error storing token:', error);
              document.body.innerHTML += '<p>Error storing authentication token. Please try again.</p>';
            }
          </script>
        </head>
        <body>
          <h1>Authentication Successful</h1>
          <p>You are being redirected to the application...</p>
        </body>
        </html>
      `);
    } catch (error) {
      console.error('Fatal error in OIDC callback:', error);
      
      return res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authentication Error</title>
          <script>
            console.error('Fatal authentication error');
            setTimeout(function() {
              window.location.href = '/signin?error=fatal_error';
            }, 3000);
          </script>
        </head>
        <body>
          <h1>Authentication Error</h1>
          <p>A fatal error occurred during authentication: ${error.message}</p>
          <p>Redirecting to sign in page...</p>
        </body>
        </html>
      `);
    }
  }

  @Post('/auth/oidc/genTokenByCode')
  @HttpCode(200)
  @UseGuards(PublicApiLimiterGuard, AuthGuard('oidc'))
  async oidcSignin(@Req() req: NcRequest, @Res() res: Response) {
    await this.setRefreshToken({ req, res });
    res.json(await this.usersService.login(req.user, req));
  }

  @Get([
    '/auth/user/me',
    '/api/v1/db/auth/user/me',
    '/api/v1/auth/user/me',
    '/api/v2/auth/user/me',
  ])
  @UseGuards(MetaApiLimiterGuard, GlobalGuard)
  async me(@Req() req: NcRequest) {
    const user = {
      ...req.user,
      roles: extractRolesObj(req.user.roles),
      workspace_roles: extractRolesObj(req.user.workspace_roles),
      base_roles: extractRolesObj(req.user.base_roles),
    };

    await PresignedUrl.signMetaIconImage(user);

    return user;
  }

  @Post([
    '/user/password/change',
    '/api/v1/db/auth/password/change',
    '/api/v1/auth/password/change',
    '/api/v2/auth/password/change',
  ])
  @UseGuards(MetaApiLimiterGuard, GlobalGuard)
  @Acl('passwordChange', {
    scope: 'org',
  })
  @HttpCode(200)
  async passwordChange(@Req() req: NcRequest, @Res() res): Promise<any> {
    if (!(req as any).isAuthenticated?.()) {
      NcError.forbidden('Not allowed');
    }

    await this.usersService.passwordChange({
      user: req['user'],
      req,
      body: req.body,
    });

    // set new refresh token
    await this.setRefreshToken({ req, res });

    res.json({ msg: 'Password has been updated successfully' });
  }

  @Post([
    '/auth/password/forgot',
    '/api/v1/db/auth/password/forgot',
    '/api/v1/auth/password/forgot',
    '/api/v2/auth/password/forgot',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async passwordForgot(@Req() req: NcRequest): Promise<any> {
    await this.usersService.passwordForgot({
      siteUrl: (req as any).ncSiteUrl,
      body: req.body,
      req,
    });

    return { msg: 'Please check your email to reset the password' };
  }

  @Post([
    '/auth/token/validate/:tokenId',
    '/api/v1/db/auth/token/validate/:tokenId',
    '/api/v1/auth/token/validate/:tokenId',
    '/api/v2/auth/token/validate/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async tokenValidate(@Param('tokenId') tokenId: string): Promise<any> {
    await this.usersService.tokenValidate({
      token: tokenId,
    });
    return { msg: 'Token has been validated successfully' };
  }

  @Post([
    '/auth/password/reset/:tokenId',
    '/api/v1/db/auth/password/reset/:tokenId',
    '/api/v1/auth/password/reset/:tokenId',
    '/api/v2/auth/password/reset/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async passwordReset(
    @Req() req: NcRequest,
    @Param('tokenId') tokenId: string,
    @Body() body: any,
  ): Promise<any> {
    await this.usersService.passwordReset({
      token: tokenId,
      body: body,
      req,
    });

    return { msg: 'Password has been reset successfully' };
  }

  @Post([
    '/api/v1/db/auth/email/validate/:tokenId',
    '/api/v1/auth/email/validate/:tokenId',
    '/api/v2/auth/email/validate/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async emailVerification(
    @Req() req: NcRequest,
    @Param('tokenId') tokenId: string,
  ): Promise<any> {
    await this.usersService.emailVerification({
      token: tokenId,
      req,
    });

    return { msg: 'Email has been verified successfully' };
  }

  @Get([
    '/api/v1/db/auth/password/reset/:tokenId',
    '/api/v2/db/auth/password/reset/:tokenId',
    '/auth/password/reset/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  async renderPasswordReset(
    @Req() req: NcRequest,
    @Res() res: Response,
    @Param('tokenId') tokenId: string,
  ): Promise<any> {
    try {
      res.send(
        ejs.render(
          (await import('~/modules/auth/ui/auth/resetPassword')).default,
          {
            ncPublicUrl: process.env.NC_PUBLIC_URL || '',
            token: tokenId,
            baseUrl: `/`,
          },
        ),
      );
    } catch (e) {
      return res.status(400).json({ msg: e.message });
    }
  }

  async setRefreshToken({ res, req }) {
    await this.usersService.setRefreshToken({ res, req });
  }
}
