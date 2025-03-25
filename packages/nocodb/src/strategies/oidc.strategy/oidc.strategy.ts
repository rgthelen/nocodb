import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '~/services/users/users.service';
import { sanitiseUserObj } from '~/utils';
import type { NcRequest } from '~/interface/config';
import type { FactoryProvider } from '@nestjs/common/interfaces/modules/provider.interface';
import { User } from '~/models';

@Injectable()
export class OidcStrategy extends PassportStrategy(Strategy, 'oidc') {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super();
  }

  // Custom validator that handles both the initial redirect and the callback
  async validate(req: NcRequest, done: any): Promise<any> {
    try {
      // Check if this is the initial auth request or a callback
      if (!req.query.code) {
        // Initial auth request - redirect to Rownd
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
        
        // Redirect to auth URL
        req.res.redirect(authUrl);
        return false; // Return false to prevent proceeding with Passport authentication
      }
      
      try {
        // Handle callback - we have a code
        console.log('OIDC Callback with code:', req.query.code);
        
        // Exchange code for token
        const tokenURL = process.env.NC_OIDC_TOKEN_URL;
        const callbackURL = process.env.NC_OIDC_CALLBACK_URL || process.env.NC_REDIRECT_URL;
        const clientID = process.env.NC_OIDC_CLIENT_ID;
        const clientSecret = process.env.NC_OIDC_CLIENT_SECRET;
        
        const formData = new URLSearchParams({
          grant_type: 'authorization_code',
          code: req.query.code as string,
          redirect_uri: callbackURL,
          client_id: clientID,
          client_secret: clientSecret,
        }).toString();
        
        console.log('Sending token request to:', tokenURL);
        
        const tokenResponse = await fetch(tokenURL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: formData,
        });
        
        if (!tokenResponse.ok) {
          const errorText = await tokenResponse.text();
          console.error('Token exchange failed:', errorText);
          return false; // Return false to prevent proceeding with Passport authentication
        }
        
        const tokenData = await tokenResponse.json();
        console.log('Received token data with keys:', Object.keys(tokenData));
        
        if (!tokenData.access_token) {
          console.error('No access token in response');
          return false;
        }
        
        // Get user info with the access token
        const userInfoURL = process.env.NC_OIDC_USERINFO_URL;
        console.log('Fetching user info from:', userInfoURL);
        
        const userInfoResponse = await fetch(userInfoURL, {
          headers: {
            'Authorization': `Bearer ${tokenData.access_token}`,
          },
        });
        
        if (!userInfoResponse.ok) {
          const errorText = await userInfoResponse.text();
          console.error('User info request failed:', errorText);
          return false;
        }
        
        const userInfo = await userInfoResponse.json();
        console.log('User info keys:', Object.keys(userInfo));
        
        // Extract email from user info
        let email = userInfo.email;
        
        if (!email) {
          console.log('No email in primary location, searching other fields');
          // Try to find any property that might contain an email
          for (const key in userInfo) {
            if (
              key.toLowerCase().includes('email') && 
              typeof userInfo[key] === 'string' &&
              userInfo[key].includes('@')
            ) {
              email = userInfo[key];
              console.log(`Found email in field ${key}: ${email}`);
              break;
            }
          }
        }
        
        if (!email && userInfo.sub) {
          // Use sub as a fallback
          email = `${userInfo.sub}@rownd-user.nocodb.com`;
          console.log('Using sub as email fallback:', email);
        } else if (!email) {
          // Generate a random email as last resort
          const uniqueId = Math.random().toString(36).substring(2);
          email = `rownd-user-${uniqueId}@nocodb.com`;
          console.log('Generated random email:', email);
        }
        
        console.log('Final email for authentication:', email);
        
        // Use User model directly instead of the service
        let user = await User.getByEmail(email);
        if (!user) {
          console.log('User not found, creating new user with email:', email);
          try {
            // Use registerNewUserIfAllowed from the User model
            user = await this.usersService.registerNewUserIfAllowed({
              email_verification_token: null,
              email,
              password: '',
              req,
            } as any);
            console.log('User created successfully');
          } catch (createError) {
            console.error('Error creating user:', createError);
            return false;
          }
        } else {
          console.log('Existing user found');
        }
        
        if (!user) {
          console.error('Failed to get or create user account');
          return false;
        }
        
        // Return sanitized user object to Passport
        const sanitizedUser = sanitiseUserObj(user);
        console.log('Authentication successful for user:', sanitizedUser.email);
        return sanitizedUser;
      } catch (innerError) {
        console.error('Error in OIDC callback processing:', innerError);
        return false;
      }
    } catch (err) {
      console.error('OIDC validation error:', err);
      return false;
    }
  }
}

export const OidcStrategyProvider: FactoryProvider = {
  provide: OidcStrategy,
  inject: [ConfigService, UsersService],
  useFactory: async (configService: ConfigService, usersService: UsersService) => {
    return new OidcStrategy(configService, usersService);
  },
}; 