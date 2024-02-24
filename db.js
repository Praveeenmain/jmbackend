const { MongoClient } = require('mongodb');
let dbConnection;
let url='mongodb+srv://praveen3456:Praveen321@cluster0.ztpgcjt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
module.exports = {
    connectToDb: (cb) => { // corrected from connectTodb to connectToDb
        MongoClient.connect(url)
            .then((client) => {
                dbConnection = client.db();
                return cb();
            })
            .catch(err => {
                console.log(err);
                return cb(err);
            });
    },
    getDb: () => dbConnection
};