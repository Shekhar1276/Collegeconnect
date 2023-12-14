const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('node:crypto');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = 3000;
const salt  = process.env.SALT;
const host = process.env.HOST;
const user = process.env.USER;
const password = process.env.PASSWORD;
const database = process.env.DATABASE;
const secret = process.env.SECRET_KEY;
// Create a MySQL connection pool
const pool = mysql.createPool({
  host: host,
  user: user,
  password: password,
  database: database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Create a user table in MySQL
const createTableQuery = `
  CREATE TABLE IF NOT EXISTS backuser (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  )
`;

pool.query(createTableQuery, (err) => {
  if (err) throw err;
  console.log('Users table created or already exists.');
});

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const storage = multer.diskStorage({
    destination: './uploads/', // Set your desired folder
    filename: (req, file, cb) => {
      cb(null, crypto.randomBytes(16).toString('hex') + path.extname(file.originalname));
    },
  });
  
  // Initialize multer
  const upload = multer({
    storage: storage,
    limits: { fileSize: 1000000 }, // Set your file size limit
  }).single('profilePicture'); 

// Passport middleware
app.use(session({
    secret: secret, // Change this to a random secret key
    resave: false,
    saveUninitialized: true
  }));

app.use(passport.initialize());
app.use(passport.session());
//app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.status(401).json({ message: 'Unauthorized' });
  };

const isAuthorized = (req, res, next) => {
    const userId = req.params.id;
  
    // Check if the authenticated user has the right to access the requested user's profile picture
    if (req.isAuthenticated() && req.user.id === userId) {
      return next();
    }
  
    res.status(403).json({ message: 'Forbidden' });
};
// Local Strategy
passport.use(new LocalStrategy(
  { usernameField: 'username', passwordField: 'password' },
  (username, password, done) => {
    pool.query('SELECT * FROM backuser WHERE username = ?', [username], (err, results) => {
      if (err) { return done(err); }
      const user = results[0];
      if (!user) { return done(null, false, { message: 'Incorrect username.' }); }
      if (user.password !== password) { return done(null, false, { message: 'Incorrect password.' }); }
      return done(null, user);
    });
  }
));

// Passport serialization/deserialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  pool.query('SELECT * FROM backuser WHERE id = ?', [id], (err, results) => {
    if (err) { return done(err); }
    const user = results[0];
    done(null, user);
  });
});

const hashPassword = (password) => {
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return `${salt}$${hash}`;
  };
const hashincomingpassword = function (req,res,next){
    if(req.body && req.body.password){
    req.body.password = hashPassword(req.body.password);
    }
    next();
}

// Signup route
app.post('/signup', (req, res) => {
  const { name , username, password} = req.body;
  const hashedpass = hashPassword(password);
  const ID = uuidv4();
  // Check if the username is already taken
  pool.query('SELECT * FROM backuser WHERE username = ?', [username], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error checking username.' });
    }

    if (results.length > 0) {
      return res.status(400).json({ message: 'Username is already taken.' });
    }

    // Create a new user
    pool.query('INSERT INTO backuser (id, name, username, password) VALUES (? ,?,?, ?)', [ID,name,username, hashedpass], (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error saving user.' });
      }
      return res.json({ message: 'Signup successful.' });
    });
  });
});

// login route
app.post('/login',hashincomingpassword , passport.authenticate('local'), (req, res) => {
    // If this function gets called, authentication was successful.
    // `req.user` contains the authenticated user
    res.status(200);
    res.send({message: 'Login successful.', user: req.user.id ,})
     //res.json({ message: 'Login successful.', user: req.user , "id" : id});
  });
  
  // Logout route
app.get('/logout', (req, res) => {
    res.status(200);
    req.logout(() => {
        res.json({ message: 'Logout successful.' });
    });
});
  
  // Check if the user is authenticated
app.get('/user/:id',isAuthenticated,isAuthorized, (req, res) => {
    const id  = req.params.id;
        pool.query('SELECT * FROM backuser WHERE id = ?', [id], (err, results) => {
            if (err) {
              return res.status(500).json({ message: 'Internal Server Error' });
            }
        const user = results[0];
        if (user) {
            // Exclude the password from the response for security
            const { password, ...userData } = user;
            res.json({ user: userData });
          } else {
            res.status(404).json({ message: 'User not found.' });
          }
        });
    });

app.get('/userprofiledata/:id' , isAuthenticated, isAuthorized ,(req,res) => {
        pool.query('SELECT * FROM userprofile WHERE id = ?', [id], (err, results) => {
            if (err) {
              return res.status(500).json({ message: 'Internal Server Error' });
            }
        const user = results[0];
        if (user) {
            // Exclude the password from the response for security
            const { password, ...userData } = user;
            res.json({ user: userData });
          } else {
            res.status(404).json({ message: 'User not found.' });
          }
        })
});



app.post('/upload/:id', isAuthenticated,isAuthorized ,(req, res) => {
    upload(req, res, (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
  
      // Check if a file was provided
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
      }
  
      const userId = req.params.id; // Assuming you have a user ID in the request body
  
      // Check if the user already has a profile picture
      pool.query('SELECT profile_picture FROM userspic WHERE id = ?', [userId], (selectError, selectResults) => {
        if (selectError) {
          return res.status(500).json({ error: 'Database error.' });
        }
  
        const user = selectResults[0];
  
        if (user && user.profile_picture) {
            const oldFilePath = path.join(__dirname, user.profile_picture);
        fs.unlink(oldFilePath, (unlinkError) => {
          if (unlinkError) {
            return res.status(500).json({ error: 'Error deleting old file.' });
          }
        });

          // Update the existing record
          const filePath = req.file.path;
          pool.query('UPDATE userspic SET profile_picture = ? WHERE id = ?', [filePath, userId], (updateError) => {
            if (updateError) {
              return res.status(500).json({ error: 'Database error.' });
            }
  
            res.json({ message: 'File updated successfully.' });
          });
        } else {
          // Insert a new record
          const filePath = req.file.path;
          pool.query('INSERT INTO userspic (id, profile_picture) VALUES (?, ?)', [userId, filePath], (insertError) => {
            if (insertError) {
              return res.status(500).json({ error: 'Database error.' });
            }
  
            res.json({ message: 'File uploaded successfully.' });
          });
        }
      });
    });
  });

// 

app.get('/profilepicture/:id', isAuthenticated, isAuthorized ,(req, res) => {
    const userId = req.params.id;
  
    // Query the database to get the profile picture path
    pool.query('SELECT profile_picture FROM userspic WHERE id = ?', [userId], (error, results) => {
      if (error) {
        return res.status(500).json({ error: 'Database error.' });
      }
  
      const user = results[0];
  
      // Check if the user and profile picture exist
      if (!user || !user.profile_picture) {
        return res.status(404).json({ message: 'User or profile picture not found.' });
      }
  
      // Send the image data
      const imagePath = path.join(__dirname, user.profile_picture);
      res.sendFile(imagePath);
    });
  });

app.get('*', (req,res) => {
    res.status(404).sendFile("C:\\Users\\ASUS\\Collegeconnect\\notfound.html");
})

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
