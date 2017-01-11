# JWT - Active Directory

**Authorization Middleware and Authenticator for Active Directory and JWT token**

[![Build Status](https://travis-ci.org/SSENSE/jwt-active-directory.svg?branch=master)](https://travis-ci.org/SSENSE/jwt-active-directory)
[![Coverage Status](https://coveralls.io/repos/github/SSENSE/jwt-active-directory/badge.svg)](https://coveralls.io/github/SSENSE/jwt-active-directory)
[![Latest Stable Version](https://img.shields.io/npm/v/@ssense/jwt-active-directory.svg)](https://www.npmjs.com/package/@ssense/jwt-active-directory)
[![Known Vulnerabilities](https://snyk.io/test/npm/@ssense/jwt-active-directory/badge.svg)](https://snyk.io/test/npm/@ssense/jwt-active-directory)

## Table of Contents
- [Installation](#installation)
- [Constructing a token](#constructing-a-token)
- [Using middleware to validate token](#using-middleware-to-validate-token)
- [Caveats](#caveats)
- [Licence](#licence)

### Ways of passing a token for validation

There are four ways to pass the token for validation: (1) in the `Authorization` header, (2) as a `cookie`, (3) as a `POST` parameter, and (4) as a `URL` query parameter.  The middleware will look in those places in the order listed and return `401` if it can't find any valid token.

| Method               | Format                            |
| -------------------- | --------------------------------- |
| Authorization Header | `Authorization: Bearer <token>`   |
| Cookie               | `"jwt_token": <token>`            |
| URL Query Parameter  | `/protected?access_token=<token>` |
| Body Parameter       | `POST access_token=<token>`       |

### Installation

```bash
npm install --save @ssense/jwt-active-directory
```

### Constructing a token

```js
const authenticator = new Authenticator({
    url: 'ldap://127.0.0.1:1389',
    baseDN: 'dc=domain,dc=com',
    username: 'auth@domain.com',
    //username: 'CN=Authenticator,OU=Special Users,DC=domain,DC=com',
    password: 'password',
    logging: {
        name: 'ActiveDirectory',
        streams: [
            {
                level: 'error',
                stream: process.stdout
            }
        ]
    }
});

authenticator.authenticate('user@domain.com', 'password')
.then(({auth, user, groups}) => {
    if (auth) {
        const token: string = authenticator.sign({user, groups}, 'no-so-secret-key', {
            expiresIn: '1 day'
        });

        // your script ...
    }
})
.catch((err) => {
    console.log(err);
});
```
or you can use `authenticateAndSign(email: string, password: string, jwtKey: string, jwtOptions, jwtExtraClaims?: {})`
```js
authenticator.authenticateAndSign('user@domain.com', 'password', 'no-so-secret-key', {
    expiresIn: '1 day'
},
// Optional claims argument
{
    extra: 'payload options',
    foo: 'bar',
    hello: 'Worl!'
})
.then(({auth, user, groups, token}) => {
    console.log('auth', auth);
    console.log('user', user);
    console.log('groups', groups);
    console.log('token', token);
})
.catch((err) => {
    console.log(err);
});
```

### Using middleware to validate token

```js
import {authenticated} from 'jwt-active-directory';

// ... your code ...

app.get('*', authenticated({
    allowed: ['*', 'Group 1', 'Antoher Group Allowed'], // list of groups allowed to enter this route
    jwtKey: 'no-so-secret-key', // your jwt secret key
    handleError: false // default true, middleware will stop res.end() and show error
}), (req, res) => {
    // your code
    // access token with **req.token**
    // do what you want we the new generate token
});
```

**Middleware default options <AuthenticatedOptions>**
```js
options = {
    allowed: [],
    jwtKey: null,
    queryKey: 'access_token',
    bodyKey: 'access_token',
    cookieKey: 'jwt_token',
    headerKey: 'Bearer',
    reqKey: 'token', // req.token
    validateGroupKey: 'cn',
    handleError: true
};
```

### Caveats

JWT validation depends only on validating the correct signature and that the token is unexpired.

### License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
