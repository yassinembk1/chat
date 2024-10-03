const express = require("express");
const multer = require('multer');
const Chat = require("./models/Chat");
const User = require("./models/User");
const Post=require('./models/Posts');
const Comments=require('./models/Comments');
const Notifications=require('./models/Notifications');
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const MongoDBSession = require("connect-mongodb-session")(session);
const cloudinary = require("./utils/Cloudinary");
const app = express();
app.use(express.static('build'));
// Middleware de traitement des fichiers
const upload = multer();

// Middleware de gestion des données de formulaire
const formData = require("express-form-data");

// Configuration de la base de données MongoDB
const mongoURI = process.env.Mongo;

// Configuration du middleware de session
const store = new MongoDBSession({
  uri: mongoURI,
  collection: "sessions",
});


// Middlewares

app.use(express.json({ limit: '50mb' })); // Augmenter la limite à 50MB
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Augmenter la limite à 50MB
app.use(bodyParser.json());
app.use(formData.parse());

// Middleware d'authentification
function isAuth(req, res, next) {
  if (req.session.isAuth) {
    next();
  } else {
    res.redirect("/login");
  }
}
app.use(
  session({
    secret: process.env.SESSION_SECRET || "defaultsecret",
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 jour
      secure: false, // 'false' en local, 'true' en production avec HTTPS
      httpOnly: true,
      sameSite: "lax", // ou 'none' pour les cookies cross-site
    },
  })
);

// Routes

// Route de connexion
// Fonction utilitaire pour trouver un utilisateur
async function findUserByEmail(email) {
  try {
    return await User.findOne({ email });
  } catch (error) {
    throw new Error('Error finding user');
  }
}
// Fonction utilitaire pour comparer les mots de passe
async function comparePasswords(inputPassword, storedPassword) {
  try {
    return await bcrypt.compare(inputPassword, storedPassword);
  } catch (error) {
    throw new Error('Error comparing passwords');
  }
}
app.get('/', (req, res) => {
  
})
// Route de connexion
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Trouver l'utilisateur par email
    const user = await findUserByEmail(email);

    // Vérifier si l'utilisateur existe
    if (!user) {
      return res.status(400).json({ message: 'User does not exist' });
    }

    // Comparer les mots de passe
    const isMatch = await comparePasswords(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Authentifier l'utilisateur
    req.session.user = user;
    req.session.isAuth = true;
    console.log('Session ID:', req.sessionID);

    // Réponse de succès
    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/name', (req, res) => {
 const name = req.session.user.fullname;
res.status(200).json({ name });
})

// Route d'enregistrement
app.post("/api/register", async (req, res) => {
  const { username, email, password, file } = req.body;

  try {
    const result = await cloudinary.uploader.upload(file, {
      folder: "user-avatar",
      allowed_formats: ["jpg", "png", "ico", "svg", "webp", "jpeg"],
    });

    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      user = new User({
        fullname: username,
        email,
        password: hashedPassword,
        profilepic: { public_id: result.public_id, url: result.secure_url },
      });
      await user.save();
      res.status(200).json({ message: 'Registration successful' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route de création d'image
app.post("/api/create",isAuth ,async (req, res) => {
  const {image,description,title}=req.body;

  try {
    const result = await cloudinary.uploader.upload(image, {
      folder: "user-posts",
      allowed_formats: ["jpg", "png", "ico", "svg", "webp", "jpeg"],
    });

    const post = new Post({
      user: req.session.user._id,
      images: { public_id: result.public_id, url: result.secure_url },
      title: title,
      body: description,
      date: Date.now(),

    })
    await post.save();


    const r= await User.findOneAndUpdate({ _id: req.session.user._id }, { $push: { posts: post._id } }, { new: true });

    if(r&&post)
    {    res.status(200).json({ message: 'Post created successfully' });
  }

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Server error' });
  }

});

app.patch('/api/like/:id', isAuth, async (req, res) => {
  try {
    const id=req.params.id;
    console.log(id);
    const reponse = await Post.findByIdAndUpdate(id, { $inc: { likes: 1 } }, { new: true });
    const r= await Notifications.create({sender:req.session.user._id,receiver:reponse.user._id,post:reponse._id,type:"like",message:`${req.session.user.fullname} liked your post`});
    //console.log(reponse);
    if(r&&reponse)
    {res.status(200).json(reponse);}
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
})

app.patch('/api/unlike/:id', isAuth, async (req, res) => {
  try {
    const id = req.params.id;
    console.log(id);
    const response = await Post.findByIdAndUpdate(id, { $inc: { likes: -1 } }, { new: true });
    res.status(200).json(response);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/comment/:id', isAuth, async (req, res) => {  
  const Postid = req.params.id
  try{
    
    const response= await Comments.create({user:req.session.user._id,post:Postid,body:req.body.comment});
    const r = await Post.findByIdAndUpdate(Postid, { $push: { comments: response._id } }, { new: true });
    //console.log(r)
    const n = await Notifications.create({sender:req.session.user._id,receiver:r.user,type:"comment",message:`${req.session.user.fullname} commented on your post`});
    if(r&& response&&n){
      res.status(200).json("success");
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  } 
})



app.get('/api/home', isAuth, async (req, res) => {
  try {
    const userId = req.session.user._id;

    // Fetch posts from the currently authenticated user
    const userPosts = await Post.find({ user: userId })
      .populate('user', 'fullname profilepic') // Populate user details for the post
      .populate({
        path: 'comments', // Populate the comments array
        populate: {
          path: 'user', // Populate the user details for each comment
          select: 'fullname profilepic' // Select fields from the user
        }
      });

    // Fetch posts from the user's friends
    const friendsPosts = await Post.find({ user: { $in: req.session.user.friends } })
      .populate('user', 'fullname profilepic') // Populate user details for the post
      .populate({
        path: 'comments', // Populate the comments array
        populate: {
          path: 'user', // Populate the user details for each comment
          select: 'fullname profilepic' // Select fields from the user
        }
      });
      

    // Combine the posts
    const combinedPosts = [...userPosts, ...friendsPosts];

    // Sort the combined posts by date in descending order
    const sortedCombinedPosts = combinedPosts
      .map(post => ({
        ...post.toObject(),
        date: post.date ? new Date(post.date) : new Date() // Convert date to Date object
      }))
      .sort((a, b) => b.date - a.date); // Sort by date in descending order

    // Send the sorted posts as a JSON response
    res.status(200).json({ posts: sortedCombinedPosts });
  } catch (error) {
    console.error("An error occurred while fetching posts:", error);
    res.status(500).json({ message: "An error occurred while fetching posts." });
  }
});








// Route de profil
app.get('/api/profile',isAuth ,async (req, res) => {
  
  const id = req.session.user._id;
  try{
    const r = await User.findById(id);
    const name=r.fullname;
    const nposts = r.posts.length;
    const nfriends = r.friends.length;
    const pic = r.profilepic.url;
    
    res.json({ nposts:nposts,nfriends:nfriends,pic:pic ,name:name});
  }catch(err){
    console.log(err);
  }
  
});

// Route de déconnexion
app.get('/api/logout',isAuth ,(req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Erreur lors de la destruction de la session :', err);
      return res.status(500).send('Erreur lors de la déconnexion');
    }
    res.clearCookie('connect.sid');
    res.status(200).json({ message: 'Deconnexion reussie' });
  });
});

app.post('/api/friendreq', isAuth, async (req, res) => {
  const { friend } = req.body; // Email to whom the request is being sent
  const userid = req.session.user._id; // ID of the currently authenticated user

  try {
    // Find the user to whom the friend request is being sent
    const userTo = await User.findOne({ email: friend });

    // Check if the user was found
    if (!userTo) {
      return res.status(400).json({ message: "User does not exist." });
    }

    // Ensure the user is not sending a request to themselves
    if (userTo._id.equals(userid)) {
      return res.status(400).json({ message: "Cannot send a friend request to yourself." });
    }

    // Check if the friend request has already been sent
    if (userTo.friendrequests.includes(userid)) {
      return res.status(400).json({ message: "Friend request already sent." });
    }

    // Update the user document by adding the friend request
    await User.updateOne({ email: friend }, { $push: { friendrequests: userid } });
    await Notifications.create({ sender: userid, receiver: userTo._id, type: "follow" , message: "sent you a friend request." });
    // Respond with success
    return res.status(200).json({ message: "Friend request sent successfully." });

  } catch (error) {
    console.error("Error processing friend request:", error);
    return res.status(500).json({ message: "Server error." });
  }
});

app.get('/api/notifications', isAuth, async (req, res) => {
  const userId = req.session.user._id; // Get the current user's ID

  try {
    // Fetch notifications where 'receiver' is the current user's ID
    // Populate relevant fields like sender details
    const notifications = await Notifications.find({ receiver: userId })
      .sort({ createdAt: -1 })
      .populate('sender', 'fullname profilepic')
      .lean();

    // Loop through notifications to check if the sender is a friend
    const updatedNotifications = await Promise.all(
      notifications.map(async (notif) => {
        const isFriend = await User.findOne({
          _id: userId,
          friends: { $in: [notif.sender._id] },
        });

        // Add 'isaccepted' field to each notification
        return { ...notif, isaccepted: isFriend };
      })
    );
      console.log(updatedNotifications)
    res.status(200).json(updatedNotifications); // Send updated notifications with 'isaccepted'
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ message: "Server error" });
  }
});


app.post('/api/accept/:id', isAuth, async (req, res) => {
  const id = req.params.id;
  console.log(id);

  try {
    const r = await User.findById(id);  // Find the user by the ID
    if (!r) {
      return res.status(404).json({ mssg: "User not found" });
    }

    const username = r.fullname;
    console.log(username);

    // Remove the friend request from the session user
    const t = await User.findOneAndUpdate(
      { email: req.session.user.email },
      { $pull: { friendrequests: id } }
    );

    if (t) {
      // Check if the user is already in the friends list
      if (t.friends.includes(id)) {
        return res.status(200).json({ mssg: "Already friends" });
      }

      // Add the friend if not already added
      const response = await User.updateOne(
        { email: req.session.user.email },
        { $push: { friends: id } }
      );
      const response2 = await User.updateOne(
        { _id: id },
        { $push: { friends: req.session.user._id } }
      );

      if (response.modifiedCount > 0 && response2.modifiedCount > 0) {
        res.status(200).json({ mssg: "You are now friends with " + username,friend:"yes" });
      } else {
        res.status(500).json({ mssg: "Failed to add friend" });
      }
    } else {
      res.status(500).json({ mssg: "Failed to update friend requests" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ mssg: "Server error" });
  }
});

app.get('/api/chat/:id',isAuth, async (req, res) => {
  const id = req.params.id;
  console.log(id);

  try {
    const r = await User.findById(id);  // Find the user by the ID
    if (!r) {
      return res.status(404).json({ mssg: "User not found" });
    }
    res.status(200).json(r);
  }  
  catch (err) {
    console.log(err);
    res.status(500).json({ mssg: "Server error" });
  }
});

app.get('/api/chatting/:id', isAuth, async (req, res) => {
  const id = req.params.id;
  const currentUserId = req.session.user._id.toString();
  const you = [];
  const friend = [];
  
  try {
    const response = await Chat.find({
      $or: [
        { sender: req.session.user._id, receiver: id },
        { sender: id, receiver: req.session.user._id }
      ]
    }).sort({ createdAt: 1 });  // Sorting by createdAt to maintain message order
      // Sorting by createdAt to maintain message order

    // Separate messages into 'you' and 'friend' based on sender
    response.forEach(message => {
      const formattedDate = new Date(message.createdAt).toLocaleString();

      if (message.sender == currentUserId) {
        you.push({ sender:currentUserId,message: message.message, createdAt: formattedDate});
      } else {
        friend.push({sender:id, message: message.message, createdAt:formattedDate });
      }
    });

    // Send the collected messages to the client
     res.status(200).json({ you, friend });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "An error occurred while fetching chat messages." });
  }
});


  app.post('/api/chat',isAuth, async (req, res) => {
    const {receiver, text } = req.body;
    try {
      const newMessage = new Chat({
        sender:req.session.user._id,
        receiver:receiver,
        message:text
      });
      await newMessage.save();
      res.status(200).json({ mssg: "Message sent" });
      
    } catch (error) {
      console.log(error);
      res.status(500).json({ mssg: "Server error" });
    }
  });



app.get('/api/followers',isAuth, async (req, res) => {
  const id = req.session.user._id;
  try{
    const resp = await User.findOne({ _id: id }).populate('friends');
    //console.log(resp.friends);
    res.status(200).json(resp.friends);
  }catch(err){
    console.log(err);
    res.status(500).json({ mssg: "Server error" });
  }
})

app.get('/api/myposts',isAuth, async (req, res) => {
  
    try {
      const userId = req.session.user._id;
  
      // Fetch posts from the currently authenticated user
      const userPosts = await Post.find({ user: userId })
        .populate('user', 'fullname profilepic') // Populate user details for the post
        .populate({
          path: 'comments', // Populate the comments array
          populate: {
            path: 'user', // Populate the user details for each comment
            select: 'fullname profilepic' // Select fields from the user
          }
        });
  
      const sortedPosts = userPosts
        .map(post => ({
          ...post.toObject(),
          date: post.date ? new Date(post.date) : new Date() // Convert date to Date object
        }))
        .sort((a, b) => b.date - a.date); // Sort by date in descending order
  
      // Send the sorted posts as a JSON response
      res.status(200).json({ posts: sortedPosts });
    } catch (error) {
      console.error("An error occurred while fetching posts:", error);
      res.status(500).json({ message: "An error occurred while fetching posts." });
    }

  
});



app.get('/api/friends',isAuth, async (req, res) => {
  const u = req.session.user 
  const friends= u.friends
  const array=[]
  
  const result = await Promise.all(
    friends.map(async (friend) => {
      const user = await User.findOne({ _id: friend });
      array.push(user);
    })
  );
  //console.log(array);
  res.status(200).json(array)

});


// Connexion à la base de données et démarrage du serveur
mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    app.listen(5000, () => console.log("Server listening on port 5000 ..."));
  })
  .catch((err) => {
    console.log(err);
  });
