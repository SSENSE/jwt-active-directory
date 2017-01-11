import {expect} from 'chai';
import {createRequest, createResponse} from 'node-mocks-http';
import * as jwt from 'jsonwebtoken';
import {authenticated, AuthenticatedOptions, ActiveDirectoryGroups, ActiveDirectoryGroup} from '../../ts';
import {JWTUndefinedError, RFC6750Error, UnauthorizedError} from '../../ts/exceptions';

describe('Authenticated middleware', () => {
    it('should failed if jwtKey is not specified', (done) => {
        const req = createRequest();
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed: [],
            jwtKey: '',
            handleError: false
        });

        auth(req, res, (err) => {
            expect(err.constructor.name).to.equal(JWTUndefinedError.name);
            expect(err.message).to.equal('JWT secret key undefined');
            done();
        });
    });

    it('should receive jwt malformed error', (done) => {
        const req = createRequest({
            headers: {
                Authorization: 'Bearer jwt.malformed'
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed: [],
            jwtKey: 'thiskeywillfailed',
            handleError: false
        });

        auth(req, res, (err) => {
            expect(err.constructor.name).to.equal(jwt.JsonWebTokenError.name);
            expect(err.message).to.equal('jwt malformed');
            done();
        });
    });

    it('should get unauthorized and status code 401 with undefined groups', (done) => {
        const jwtKey = 'no-so-secret-key';
        const token = jwt.sign({}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed: [],
            jwtKey,
            handleError: false
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(401);
            expect(err.constructor.name).to.equal(UnauthorizedError.name);
            expect(err.message).to.equal('Unauthorized');
            done();
        });
    });

    it('should failed if user don\'t have group rights', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'FailedGroup' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(401);
            expect(err.constructor.name).to.equal(UnauthorizedError.name);
            expect(err.message).to.equal('Unauthorized');
            done();
        });
    });

    it('should succeed if groups allowed from header Authorization bearer', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.token).to.equal(token);
            done();
        });
    });

    it('should succeed if groups allowed from query access_token', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            query: {
                access_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.token).to.equal(token);
            done();
        });
    });

    it('should succeed if groups allowed from body access_token', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            body: {
                access_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.token).to.equal(token);
            done();
        });
    });

    it('should failed if token is passed with query and body', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            query: {
                access_token: token
            },
            body: {
                access_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(400);
            expect(err.constructor.name).to.equal(RFC6750Error.name);
            expect(err.message).to.equal('RFC6750 The "token" attribute MUST NOT appear more than once');
            done();
        });
    });

    it('should failed if token is passed with query and headers', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            query: {
                access_token: token
            },
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            handleError: false
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(400);
            expect(err.constructor.name).to.equal(RFC6750Error.name);
            expect(err.message).to.equal('RFC6750 The "token" attribute MUST NOT appear more than once');
            done();
        });
    });

    it('should failed is token header has no whitespace after bearer', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'FailTest' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            headers: {
                Authorization: `Bearer${token}`
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(400);
            expect(err.constructor.name).to.equal(RFC6750Error.name);
            expect(err.message).to.equal('Authorization Bearer header could not be splitted');
            done();
        });
    });

    it('should succeed if jwt_token is found in cookies', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            cookies: {
                jwt_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.token).to.equal(token);
            done();
        });
    });

    it('should failed if jwt_token is found in cookies and in body', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            cookies: {
                jwt_token: token
            },
            body: {
                access_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey
        });

        auth(req, res, (err) => {
            expect(res.statusCode).to.equal(400);
            expect(err.constructor.name).to.equal(RFC6750Error.name);
            expect(err.message).to.equal('RFC6750 The "token" attribute MUST NOT appear more than once');
            done();
        });
    });

    it('should succeed if custom cookie name is found in cookies', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            cookies: {
                custom_cookie_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            cookieKey: 'custom_cookie_token'
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.token).to.equal(token);
            done();
        });
    });

    it('should succeed if cookie is found and pass to custom req key', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['Test'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            cookies: {
                jwt_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            reqKey: 'myCustomToken'
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.myCustomToken).to.equal(token);
            done();
        });
    });

    it('Should allow all valid token if wildcard * is set', (done) => {
        const jwtKey: string = 'no-so-secret-key';
        const allowed: string[] = ['*'];
        const groups: ActiveDirectoryGroups = [<ActiveDirectoryGroup> { cn: 'Test' }];
        const token: string = jwt.sign({groups}, jwtKey, {expiresIn: '1 hour'});

        const req = createRequest({
            cookies: {
                jwt_token: token
            }
        });
        const res = createResponse();
        const auth = authenticated(<AuthenticatedOptions> {
            allowed,
            jwtKey,
            reqKey: 'myCustomToken'
        });

        auth(req, res, () => {
            expect(res.statusCode).to.equal(200);
            expect(req.myCustomToken).to.equal(token);
            done();
        });
    });
});
