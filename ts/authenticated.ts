import * as jwt from 'jsonwebtoken';
import {AuthenticatedOptions, ActiveDirectoryGroups, ActiveDirectoryGroup} from './types';
import {JWTUndefinedError, RFC6750Error, UnauthorizedError} from './exceptions';

export function authenticated (options?: AuthenticatedOptions) {
    options = <AuthenticatedOptions>Object.assign({}, {
        allowed: [],
        jwtKey: null,
        queryKey: 'access_token',
        bodyKey: 'access_token',
        cookieKey: 'jwt_token',
        headerKey: 'Bearer',
        reqKey: 'token',
        validateGroupKey: 'cn',
        handleError: true
    }, options);

    return (req, res, next?) => {
        let token: string;
        let error: Error;

        if (!options.jwtKey) {
            error = new JWTUndefinedError('JWT secret key undefined');
        }

        if (req.query && req.query[options.queryKey]) {
            token = req.query[options.queryKey];
        }

        if (req.body && req.body[options.bodyKey]) {
            if (token) {
                error = new RFC6750Error('RFC6750 The "token" attribute MUST NOT appear more than once');
            }

            token = req.body[options.bodyKey];
        }

        if (req.cookies && req.cookies[options.cookieKey]) {
            if (token) {
                error = new RFC6750Error('RFC6750 The "token" attribute MUST NOT appear more than once');
            }

            token = req.cookies[options.cookieKey];
        }

        if (req.headers && req.headers.authorization) {
            const parts = req.headers.authorization.split(' ');

            if (parts.length === 2 && parts[0] === options.headerKey) {
                if (token) {
                    error = new RFC6750Error('RFC6750 The "token" attribute MUST NOT appear more than once');
                }

                token = parts[1];
            } else {
                error = new RFC6750Error('Authorization Bearer header could not be splitted');
            }
        }

        // RFC6750 states the access_token MUST NOT be provided
        // in more than one place in a single request.
        if (error) {
            res.status(400);
            if (options.handleError) {
                res.send({error: error.message});
                res.end();
                return;
            }
            next(error);
            return;
        }
        // Add token to request
        req[options.reqKey] = token;

        // Validate jwt token
        try {
            const decoded = jwt.verify(token, options.jwtKey);
            const groups: ActiveDirectoryGroups = decoded.groups || [];
            // if allowed all
            if (options.allowed.indexOf('*') >= 0) {
                groups.push(<ActiveDirectoryGroup> {
                    [options.validateGroupKey]: '*'
                });
            }

            const filtered = groups
                .filter((group: ActiveDirectoryGroup) => { return options.allowed.includes(group[options.validateGroupKey]); })
                .map((group: ActiveDirectoryGroup) => { return group.cn; }); // convert objects to strings

            if (!filtered.length) {
                throw new UnauthorizedError('Unauthorized');
            }

            next();
            return;
        } catch(err) {
            res.status(401);
            if (options.handleError) {
                res.send({error: err.message});
                res.end();
                return;
            }

            next(err);
            return;
        }
    }
}
