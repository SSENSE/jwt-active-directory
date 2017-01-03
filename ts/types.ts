// Authenticator: Active Directory
export type ActiveDirectoryConfig = {
    url: string;
    baseDN: string;
    username: string;
    password: string;
    logging?: Object;
};

export type ActiveDirectoryGroups = ActiveDirectoryGroup[];

export type ActiveDirectoryGroup = {
    dn?: string;
    cn: string;
    description?: string;
};

export type ActiveDirectoryUser = {
    dn: string;
    userPrincipalName: string;
    sAMAccountName: string;
    lockoutTime: string;
    whenCreated: string;
    pwdLastSet: string;
    userAccountControl: string;
    sn: string;
    givenName: string;
    cn: string;
    displayName: string;
};

export type AuthenticatorResponse = {
    auth: boolean;
    user?: ActiveDirectoryUser;
    groups?: ActiveDirectoryGroups;
    token?: string;
};

// Middleware options
export type AuthenticatedOptions = {
    allowed: string[];
    jwtKey?: string;
    queryKey?: string;
    bodyKey?: string;
    cookieKey?: string;
    headerKey?: string;
    reqKey?: string;
    validateGroupKey?: string;
    handleError?: boolean;
};
