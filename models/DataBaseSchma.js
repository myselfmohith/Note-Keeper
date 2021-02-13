const mongoose = require('mongoose');


const DatSchma = new mongoose.Schema({
    title: String,
    content: String,
    date: String
});

const UserSchma = new mongoose.Schema({
    name: String,
    username: String,
    password: String,
    clips: [DatSchma]
});

module.exports = new mongoose.model('userclip', UserSchma);