const config = {
    PORT: 64064,
    MONGO: {
        AUTH: createMongoDBConnectionObject('coa-auth25-lab', 'TDE#b!v+N9tz93Bd', 'auth')
    },
    CRYPTO: {
        SECRET: "$nw|n<+_VpM_;}#-c<t=K<Fz+bHs+=:l"
    },
    JWT: {
        SECRET: '7Zoq0Dc6QT]w}kL8**b^U)HeQ"e~u{%oxfFQUT]K5C1P]TQJ$@SSu1_p./RWM8k'
    },
    COOKIE: {
        SECRET: 'eeXaCqlqehswHwSnGQwV9ccJwTJ8mlbrbcdlV5J31oMF1FzzDhuTtQRS14KTyTTc'
    },
    MAIL: {
        HOST: "eleven.ssl.hosttech.eu",
        PORT: 465,
        SECURE: true,
        AUTH: {
            user: "noreply@lab9.ch",
            pass: "G9M=*ABm%?m&WMVX"
        }
    }
};

module.exports = config;

/**
 * Creates a mongodb connection string
 * @param username the username
 * @param password the password
 * @param database the database name
 * @param host
 * @param options
 * @returns {{CONNECTION_STRING: *, DATA: *, OPTIONS: *}}
 */
function createMongoDBConnectionObject(username, password, database, host = '127.0.0.1', options = createDefaultConnectionOptions()) {
    const data = {
        USER: username,
        PASS: password,
        DB: database,
        URL: host,
        PORT: 27017
    };
    const string = `mongodb://${data.USER}:${data.PASS}@${data.URL}:${data.PORT}/${data.DB}`;
    return {
        DATA: data,
        CONNECTION_STRING: string,
        OPTIONS: options,
        CALLBACK: (err) => {
            if (err)
                console.error("Error occurred in: " + data.DB + "\n" + err);
            else
                console.log(data.DB + " connected.")
        }
    };
}

/**
 * Create a default connection options object,
 * including the new url parser, the unified topology
 * and create index method
 *
 * @returns {{useUnifiedTopology: boolean, useCreateIndex: boolean, useNewUrlParser: boolean}}
 */
function createDefaultConnectionOptions() {
    return {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true
    }
}
