// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {authenticate, TokenService} from '@loopback/authentication';
import {
  Credentials,
  MyUserService,
  TokenServiceBindings,
  // User,
  UserRepository,
  UserServiceBindings,
} from '@loopback/authentication-jwt';
import {inject} from '@loopback/core';
import {NewUserRequest} from '../models/user.model';
import {repository} from '@loopback/repository';
import {get, post, requestBody, SchemaObject} from '@loopback/rest';
import {SecurityBindings, UserProfile} from '@loopback/security';
import {genSalt, hash, compareSync} from 'bcryptjs';
// import _ from 'lodash';

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: {
      type: 'string',
      format: 'email',
    },
    password: {
      type: 'string',
      minLength: 8,
    },
  },
};

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': {schema: CredentialsSchema},
  },
};

export class UserController {
  constructor(
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: TokenService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(SecurityBindings.USER, {optional: true})
    public user: UserProfile,
    @repository(UserRepository) protected userRepository: UserRepository,
  ) {}

  @post('/auth/login')
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<object> {
    try {
      const filter = {
        where: {
          email: credentials.email,
        },
      };

      const foundUser = await this.userRepository.findOne(filter);

      if (!foundUser) {
        return {
          status: 'error',
          message: `${credentials.email} is not yet registered.`,
        };
      }

      const isPasswordCorrect = compareSync(
        credentials.password,
        foundUser.password,
      );

      if (!isPasswordCorrect) {
        return {
          status: 'error',
          message: 'Invalid password.',
        };
      }

      const user = await this.userService.verifyCredentials(credentials);

      // convert a User object into a UserProfile object (reduced set of properties)
      const userProfile = this.userService.convertToUserProfile(user);

      // create a JSON Web Token based on the user profile
      const token = await this.jwtService.generateToken(userProfile);
      return {
        status: 'ok',
        token,
      };
    } catch (error) {
      return error;
    }
  }

  @authenticate('jwt')
  @get('/user')
  async getUserDetails(
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
  ): Promise<object> {
    const userId = currentUserProfile.id;
    const foundUser = await this.userRepository.findById(userId);
    // console.log(this.user)
    return {
      ...foundUser,
      password: undefined,
    };
  }

  @post('/auth/register')
  async signUp(
    @requestBody()
    newUserRequest: NewUserRequest,
  ) {
    const {email, password} = newUserRequest;
    const [username] = email.split('@');

    const filter = {
      where: {
        email: email,
      },
    };

    const foundUser = await this.userRepository.findOne(filter);

    if (foundUser) {
      return {
        status: 'error',
        message: `${email} is already registered`,
      };
    }

    const hashedPw = await hash(password, await genSalt());
    const savedUser = await this.userRepository.create({
      ...newUserRequest,
      username,
      password: hashedPw,
    });

    await this.userRepository
      .userCredentials(savedUser.id)
      .create({password: hashedPw});

      const user = await this.userService.verifyCredentials(newUserRequest);

      // convert a User object into a UserProfile object (reduced set of properties)
      const userProfile = this.userService.convertToUserProfile(user);

      // create a JSON Web Token based on the user profile
      const token = await this.jwtService.generateToken(userProfile);

    return {
      status: 'ok',
      token: token,
    };
  }
}
