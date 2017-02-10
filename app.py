import os
import re
from string import letters
import random
import hashlib
import hmac

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Hash using secret value
def make_secure_val(val):
    secret = 'fart'
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Hash using salt
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


# Render related
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Check validity for user account, password and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Data Model for the user
class User(db.Model):
    """
    The User object has three attributes:
        name: a String value, which is the name of the user
        pw_hash: a String value, which is the hashcode of user's password
        email: a String value, which is the user's email
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # Define a method for fast retrieving a user by its id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    # Define a method for fast retrieving a user by its name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name = ', name).get()
        return u

    # Define a method for register the user, that is creating a new user
    # in the datastore, and return this user object just created
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    # Define a method for logining the user
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Data Model for the Post
class Post(db.Expando):
    """
    The Post object has seven attributes, which are:
        author: a String value, the name of the author of the post
        subject: a String value, the title of that post
        content: a Text value, the content of that post
        created: a DateTime value, creating time of the post
        last_modified: a DataTime value, last modified time of the post
        like_count: an Integer value, how many users are liking this post
        like_users: a List of Strings, containing name of users who like the post  # NOQA
    """
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    like_count = db.IntegerProperty(required=True)
    like_users = db.StringListProperty(required=True)

    # Replace the '\n' with '<br>' in post content and render it to html
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# Data Model for the comment
class Comment(db.Model):
    """
    The Comment object has four attributes, which are:
        belong_post: a Reference Property, indicates which post it belongs to
        user_name: a String value, name of the user who made this comment
        text: a Text value, the content of this comment
        created: a DataTime value, when was this comment created
    """
    belong_post = db.ReferenceProperty(Post, collection_name="comments")
    user_name = db.StringProperty(required=True)
    text = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


# parent is used for strong consistency when using ancestor query
def blog_key(name="default"):
    return db.Key.from_path("blogs", name)


# BlogHandler is the basic handler, which will be inherited by other handlers
class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Define a method for setting cookie value
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Deifine a method for reading cookie from the browser
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Define a method for logining the user, that is setting cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Define a method for logging out the user, that is clearing cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Each time the server receive a request read cookie value from browser
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # Define a method for checking if the current user owns the current post
    def check_post_ownership(self, post):
        # check if the current user is logged in and post is valid and
        # the current user is the owner of the post
        if not self.user:
            # user needs to be logged in before editing a post
            self.redirect('/login')
            return False

        elif not post:
            # we cannot find the post, so we redirect to the front page
            self.redirect('/blog')
            return False

        elif self.user.name != post.author:
            # the logged in user is not the author of this post
            self.redirect('/blog')
            return False

        else:
            # user is logged in, post is valid, and user is its author
            # everything is fine
            return True

    # Define a method to check if the current user owns the current comment
    def check_comment_ownership(self, post, comment):
        # check if user is logged in, and post is valid,
        # and comment is valid, and user is the author of the comment
        if not self.user:
            # user needs to be logged in before editing a post
            self.redirect('/login')
            return False

        elif not post or not comment:
            # we cannot find the post or the comment,
            # so we redirect to the front page
            self.redirect('/blog')
            return False

        elif self.user.name != comment.user_name:
            # current user is not the author of this comment
            self.redirect('/blog')
            return True

        else:
            # everything is fine, current user owns this comment
            return True


# Route Handler for MainPage, we just redirect to the front page
class MainPage(BlogHandler):
    def get(self):
        self.redirect("/blog")


# Route Handler for front page, we list all the posts
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order("-created")
        posts.ancestor(blog_key())
        self.render('front.html', posts=posts)


# Route Handler for the post page, we find the render that post
class PostPage(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            self.render("not_found.html")
        else:
            self.render("permalink.html", post=post, user=self.user)


# Route Handler for creating a new post
class NewPost(BlogHandler):
    def get(self):
        # User needs to be logged in to create a post
        if self.user:
            # We render a form for adding new post
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        # When sending the form to create a new post,
        # we still check if user is logged in
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        # make sure subject and content not empty
        if subject and content:
            post = Post(parent=blog_key(),
                        author=self.user.name,
                        subject=subject,
                        content=content,
                        like_count=0,
                        like_users=[])
            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


# Route Handler for editing a post
class EditPost(BlogHandler):
    # Read the post_id from URL and search the post in the datastore
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # only proceed if the current user is the author of the post
        if self.check_post_ownership(post):
            self.render("editpost.html",
                        post_id=post.key().id(),
                        subject=post.subject,
                        content=post.content)

    # Send the form to update the post information
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # only proceed if the current user is the author of the post
        if self.check_post_ownership(post):
            subject = self.request.get("subject")
            content = self.request.get("content")
            if not subject or not content:
                # user must input both subject and content for this blog
                error = "Please fill in both subject and content"
                self.render("editpost.html",
                            subject=post.subject,
                            content=post.content,
                            error=error)
            else:
                # everything is fine, we update this post in our datastore
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))


# Route Handler for deleting a post
class DeletePost(BlogHandler):
    # Read the post_id in the URL and search the post in the datastore
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # only proceed if the current user is the author of the post
        if self.check_post_ownership(post):
            # everything is fine, we allow this user to delete this post
            # first delete all the comments associated with this blog
            for comment in post.comments:
                comment.delete()
            # then delete the post itself
            post.delete()
            return self.redirect('/blog')


# Route Handler for Liking a post
class LikePost(BlogHandler):
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # user needs to log in before liking a post
        if not self.user:
            return self.redirect('/login')
        # cannot find this post, redirect to front page
        elif not post:
            return self.redirect('/blog')
        # user is logged in and we found the post
        else:
            # this user is the author of the post
            if self.user.name == post.author:
                vote_error = "sorry, you can't like your own post"
                self.render("permalink.html",
                            post=post,
                            user=self.user,
                            vote_error=vote_error)
            # this user already liked this post
            elif self.user.name in post.like_users:
                vote_error = "sorry, you have already liked this post"
                self.render("permalink.html",
                            post=post,
                            user=self.user,
                            vote_error=vote_error)
            # everything is ok, the user can like the post
            else:
                post.like_count += 1
                post.like_users.append(self.user.name)
                post.put()
                return self.redirect("/blog/%s" % str(post_id))


# Route Handler for disliking a post
class UnlikePost(BlogHandler):
    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # user needs to log in before liking a post
        if not self.user:
            return self.redirect('/login')
        # cannot find this post, redirect to front page
        elif not post:
            return self.redirect('/blog')
        # user is logged in and we found the post
        else:
            # this user hasn't liked the post, so he cannot unlike it
            if self.user.name not in post.like_users:
                vote_error = "sorry, you haven't liked this post yet"
                self.render("permalink.html", post=post, vote_error=vote_error)
            # everything is ok, the user can unlike this post
            else:
                post.like_count -= 1
                post.like_users.remove(self.user.name)
                post.put()
                return self.redirect("/blog/%s" % str(post_id))


# Route Handler for adding a new comment to a post
class NewComment(BlogHandler):
    def get(self, post_id):
        # first read post_id from URL and search for the post in datastore
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # user needs to log in and post needs to be valid
        if not self.user:
            return self.redirect('/login')
        elif not post:
            return self.redirect('/blog')
        else:
            # everything is fine, we render the form for adding a comment
            self.render("newcomment.html", post_id=int(post_id))

    def post(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # make sure post is found and user is logged in
        if not self.user or not post:
            return self.redirect('/blog')
        else:
            text = self.request.get("text")
            # make sure comment text is not empty
            if not text:
                error = "Please fill in your comment text!"
                self.render("newcomment.html", error=error)
            else:
                user_name = self.user.name
                comment = Comment(parent=blog_key(),
                                  belong_post=post,
                                  user_name=user_name,
                                  text=text)
                comment.put()
                return self.redirect('/blog/%s' % str(post_id))


# Route Handler for editing a comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        # Again, the related post and comment itself needs to be found first
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=blog_key())
        if self.check_comment_ownership(post, comment):
            # only render the edit comment form, when the user owns the comment
            self.render("editcomment.html",
                        post_id=post.key().id(),
                        text=comment.text)

    def post(self, post_id, comment_id):
        # Again, the related post and comment itself needs to be found first
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=blog_key())
        if self.check_comment_ownership(post, comment):
            # only proceed if the user owns this comment
            text = self.request.get("text")
            # Still make sure new comment text is not empty
            if not text:
                error = "Please fill in comment text!"
                self.render("editcomment.html", error=error)
            else:
                comment.text = text
                comment.put()
                return self.redirect('/blog/%s' % str(post_id))


# Route Handler for deleting a comment
class DeleteComment(BlogHandler):
    # Again, the related post and comment itself needs to be found first
    def post(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=blog_key())
        if self.check_comment_ownership(post, comment):
            # only allow deleting when the current user owns the comment
            comment.delete()
            return self.redirect('/blog/%s' % str(post_id))


# Route Handler for signing up the user, it will be inherited by Register class
class Signup(BlogHandler):
    # Render the signup form
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # check if all the user information is valid
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            # if there is error re-render the form
            self.render('signup-form.html', **params)
        else:
            # everything is fine, finish the signup process
            self.done()

    def done(self, *a, **kw):
        # No worry, this method will be overwritten by its child class
        raise NotImplementedError


# Route Handler that inherits Signup class, this actually put user into DB
class Register(Signup):
    # We overwrite the done method here
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            # Login(u) means we create cookie for that user
            self.login(u)
            self.redirect('/welcome')


# Route Hanlder for logging in the user
class Login(BlogHandler):
    # Render the login form
    def get(self):
        self.render('login-form.html')

    # Send the form to check if user information is valid
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # Check if user is valid
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            # re-render the form if something is wrong
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# Route Handler for logging out the user
class Logout(BlogHandler):
    def get(self):
        # Only thing we do is to clear the cookie and redirect to login page
        self.logout()
        self.redirect('/login')


# Route Handler for the welcome page
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            # make sure only signed in user can reach welcome page
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/([0-9]+)/unlike', UnlikePost),
                               ('/blog/([0-9]+)/comment/new', NewComment),
                               ('/blog/([0-9]+)/comment/([0-9]+)/edit', EditComment),  # NOQA
                               ('/blog/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),  # NOQA
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)