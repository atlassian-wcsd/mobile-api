export interface AppleUser {
  id: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  isPrivateEmail?: boolean;
  authToken: string;
  refreshToken?: string;
  expiresAt: Date;
  createdAt: Date;
  lastLoginAt: Date;
}

export interface AppleTokenPayload {
  iss: string; // Issuer (Apple)
  aud: string; // Audience (your app's client ID)
  exp: number; // Expiration time
  iat: number; // Issued at time
  sub: string; // Subject (user identifier)
  email?: string;
  email_verified?: boolean;
  is_private_email?: boolean;
  auth_time: number;
  nonce_supported?: boolean;
}

export interface AppleAuthRequest {
  identityToken: string;
  authorizationCode: string;
  user?: {
    name?: {
      firstName?: string;
      lastName?: string;
    };
    email?: string;
  };
  state?: string;
}

export interface AppleAuthResponse {
  success: boolean;
  user?: AppleUser;
  error?: string;
  message?: string;
}

export class AppleUserBuilder {
  private user: Partial<AppleUser> = {};

  setId(id: string): AppleUserBuilder {
    this.user.id = id;
    return this;
  }

  setEmail(email: string): AppleUserBuilder {
    this.user.email = email;
    return this;
  }

  setName(firstName?: string, lastName?: string): AppleUserBuilder {
    this.user.firstName = firstName;
    this.user.lastName = lastName;
    this.user.fullName = [firstName, lastName].filter(Boolean).join(' ');
    return this;
  }

  setAuthToken(token: string): AppleUserBuilder {
    this.user.authToken = token;
    return this;
  }

  setRefreshToken(refreshToken: string): AppleUserBuilder {
    this.user.refreshToken = refreshToken;
    return this;
  }

  setExpiresAt(expiresAt: Date): AppleUserBuilder {
    this.user.expiresAt = expiresAt;
    return this;
  }

  setIsPrivateEmail(isPrivate: boolean): AppleUserBuilder {
    this.user.isPrivateEmail = isPrivate;
    return this;
  }

  build(): AppleUser {
    const now = new Date();
    
    if (!this.user.id || !this.user.authToken) {
      throw new Error('Apple user must have id and authToken');
    }

    return {
      id: this.user.id,
      email: this.user.email,
      firstName: this.user.firstName,
      lastName: this.user.lastName,
      fullName: this.user.fullName,
      isPrivateEmail: this.user.isPrivateEmail || false,
      authToken: this.user.authToken,
      refreshToken: this.user.refreshToken,
      expiresAt: this.user.expiresAt || new Date(now.getTime() + 3600000), // 1 hour default
      createdAt: now,
      lastLoginAt: now
    };
  }
}