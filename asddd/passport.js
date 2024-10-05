const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/User');
const bcrypt = require('bcrypt');

function initialize(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            // Find the user by email
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }

            // Check if the user's password is correct
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Password incorrect' });
            }

            // Check if the user's email is confirmed
            if (!user.isConfirmed) {
                return done(null, false, { message: 'Email not confirmed' });
            }

            // If everything is fine, return the user
            return done(null, user);
        } catch (error) {
            console.error("Authentication error:", error);
            return done(error);
        }
    };

    // Use the local strategy for authentication
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));

    // Serialize the user to store in the session
    passport.serializeUser((user, done) => {
        console.log("Serializing user:", user); // Debugging log
        done(null, user._id); // Use user._id for MongoDB
    });

    // Deserialize the user from the session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            if (!user) {
                return done(new Error('User not found'), null);
            }
            console.log("Deserialized user:", user); // Debugging log
            done(null, user);
        } catch (error) {
            console.error("Deserialization error:", error);
            done(error, null);
        }
    });
}

module.exports = initialize;
