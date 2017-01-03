import {expect} from 'chai';
import {Authenticator, ActiveDirectoryConfig} from '../../ts';
let server = require('../mockServer');

describe('Authenticator active directory auth manager', () => {
    const testConfig: ActiveDirectoryConfig = {
        url: 'ldap://127.0.0.1:1389',
        baseDN: 'dc=domain,dc=com',
        username: 'auth@domain.com',
        //username: 'CN=Authenticator,OU=Special Users,DC=domain,DC=com',
        password: 'password',
        logging: {
            name: 'ActiveDirectory',
            streams: [
                { level: 'error',
                    stream: process.stdout }
            ]
        }
    };
    const settings = require('../mockServer/settings').authenticate;
    let authenticator: Authenticator;

    before('constructor Authenticator', (done) => {
        server(function(s) {
            authenticator = new Authenticator(testConfig);
            server = s;
            done();
        });
    });

    it('succeed to authenticate', (done) => {
        authenticator.authenticate(settings.username.userPrincipalName, settings.password)
            .then(({auth, user, groups}) => {
                expect(auth).to.eq(true);
                expect(user).to.not.eq(undefined);
                expect(user.mail).to.eq(settings.username.userPrincipalName);
                expect(groups).to.not.eq(undefined);
                done();
            })
            .catch((err) => {
                done(err);
            });
    });

    it('failed to authenticate', (done) => {
        authenticator.authenticate('failed@domain.com', 'failed')
            .then(({auth, user, groups}) => {
                expect(auth).to.eq(false);
                expect(user).to.eq(undefined);
                expect(groups).to.eq(undefined);
                done();
            })
            .catch((err) => {
                done(err);
            });
    });

    it('should failed if user is not found', (done) => {
        authenticator.findUser('failed@domain.com')
            .catch((err) => {
                expect(err.message).to.eq('entry (SearchEntry) required');
                done();
            });
    });

    it('should failed if user is not found', (done) => {
        authenticator.getGroupMembershipForUser('failed@domain.com')
            .catch((err) => {
                expect(err.message).to.eq('entry (SearchEntry) required');
                done();
            });
    });

    it('should sign user if auth succeed',  (done) => {
        authenticator.authenticate(settings.username.userPrincipalName, settings.password)
            .then(({auth, user, groups}) => {
                if (auth) {
                    const token: string = authenticator.sign({user, groups}, 'no-so-secret-key', {
                        expiresIn: '1 day'
                    });

                    expect(token).to.be.a('string');
                    done();
                }
            })
            .catch((err) => {
                done(err);
            });
    });

    it('should sign user if auth succeed with callback',  (done) => {
        authenticator.authenticate(settings.username.userPrincipalName, settings.password)
            .then(({auth, user, groups}) => {
                if (auth) {
                    authenticator.sign({user, groups}, 'no-so-secret-key', {
                        expiresIn: '1 day'
                    }, (err, token) => {
                        expect(token).to.be.a('string');
                        done();
                    });
                }
            })
            .catch((err) => {
                done(err);
            });
    });

    it('should authenticate and sign user',  (done) => {
        authenticator.authenticateAndSign(settings.username.userPrincipalName, settings.password, 'no-so-secret-key', {
            expiresIn: '1 day'
        })
            .then(({auth, user, groups, token}) => {
                expect(auth).to.eq(true);
                expect(user).to.not.eq(null);
                expect(user.mail).to.eq(settings.username.userPrincipalName);
                expect(groups).to.not.eq(null);
                expect(token).to.be.a('string');
                done();
            })
            .catch((err) => {
                done(err);
            });
    });

    it('should failed if authenticate and sign user failed',  (done) => {
        authenticator.authenticateAndSign('failed@domain.com', 'failed', 'no-so-secret-key', {
            expiresIn: '1 day'
        })
            .then(({auth, user, groups, token}) => {
                expect(auth).to.eq(false);
                expect(user).to.eq(undefined);
                expect(groups).to.eq(undefined);
                expect(token).to.eq(undefined);
                done();
            })
            .catch((err) => {
                done(err);
            });
    });
});
