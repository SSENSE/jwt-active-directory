import * as ActiveDirectory from 'activedirectory';
import * as jwt from 'jsonwebtoken';
import {ActiveDirectoryConfig, ActiveDirectoryGroups, AuthenticatorResponse} from './types';

export class Authenticator {
    protected ad;

    constructor(config: ActiveDirectoryConfig) {
        this.ad = new ActiveDirectory(config);
    }

    public async authenticate(email: string, password: string): Promise<boolean|any> {
        try {
            const auth: boolean = await this.authenticateAD(email, password);
            const user: any = await this.findUser(email);
            const groups: ActiveDirectoryGroups = await this.getGroupMembershipForUser(email);
            return Promise.resolve(<AuthenticatorResponse> {
                auth,
                user,
                groups
            });
        } catch (err) {
            return Promise.resolve(<AuthenticatorResponse> {
                auth: false
            });
        }
    }

    public async authenticateAndSign(email: string, password: string, jwtKey: string, jwtOptions, jwtExtraPayload?: {}): Promise<boolean|any> {
        try {
            const auth: boolean = await this.authenticateAD(email, password);
            const user: any = await this.findUser(email);
            const groups: ActiveDirectoryGroups = await this.getGroupMembershipForUser(email);
            const token = this.sign(
                Object.assign({}, jwtExtraPayload, {user, groups}),
                jwtKey,
                jwtOptions
            );
            return Promise.resolve(<AuthenticatorResponse> {
                auth,
                user,
                groups,
                token,
            });
        } catch (err) {
            return Promise.resolve(<AuthenticatorResponse> {
                auth: false
            });
        }
    }

    public sign(payload, secretOrPrivateKey, options, callback?): string {
        return jwt.sign(payload, secretOrPrivateKey, options, callback);
    }

    public async authenticateAD(user, password): Promise<boolean> {
        return new Promise<boolean>((resolve, reject) => {
            this.ad.authenticate(user, password, (err, auth) => err ? reject(err) : resolve(!!auth));
        });
    }

    public async findUser(user): Promise<any> {
        return new Promise<any>((resolve, reject) => {
            this.ad.findUser(user, (err, user) => err ? reject(err) : resolve(user));
        });
    }

    public async getGroupMembershipForUser(user): Promise<any> {
        return new Promise<any>((resolve, reject) => {
            this.ad.getGroupMembershipForUser(user, (err, groups) => err ? reject(err) : resolve(groups));
        });
    }
}
