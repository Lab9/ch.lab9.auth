const environment = {
    port: 64064,
    mongo: {
        auth: createConnectionObject('coa-auth25-lab', 'TDE#b!v+N9tz93Bd', 'auth'),
        session: createConnectionObject('coa-session86-lab', 'QHPhLEfNdm5vs8AU', 'session'),
    },
    jwt: {
        secret: '7Zoq0Dc6QT]w}kL8**b^U)HeQ"e~u{%oxfFQUT]K5C1P]TQJ$@SSu1_p./RWM8k'
    },
    session: {
        secret: '?"X^)V:]2Q4e)91e,8_:`1b8ytn^(tTs?9NP%dPi8^/`8=2s[p)@rFhlnqLM06b',
        reSave: true,
        saveUninitialized: false,
        cookie: {
            secure: true
        }
    }
};

module.exports = environment;

function createConnectionObject(username, password, database) {
    const data = {
        username: username,
        password: password,
        database: database,
        url: '127.0.0.1',
        port: 27017
    };
    data.connectionString = `mongodb://${data.username}:${data.password}@${data.url}:${data.port}/${data.database}`;
    return data;
}
