import jinja2
import os
import webapp2
import re
import random
import string
import hashlib
import datetime

from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
COOKIE_RE = re.compile(r'.+=;\s*Path=/')

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw):
    salt = make_salt()
    hashtext = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (hashtext, salt)


def valid_pw(name, pw, hashtext, salt):
    return hashlib.sha256(name + pw + salt).hexdigest() == hashtext


def valid_cookie(cookie):
    return cookie and len(cookie)  # COOKIE_RE.match(cookie)


def get_user_from_cookie(self):
    cookie = self.request.cookies.get('login')
    if valid_cookie(cookie):
        user_id = cookie.split('|')[0]
        user = Users.get_by_id(int(user_id))
        if user.username:
            return str(user.username)
        else:
            return "Anonymous"
    else:
        return "Anonymous"


class Users(db.Model):
    username = db.StringProperty()
    hashtext = db.StringProperty()
    salt = db.StringProperty()
    email = db.StringProperty()
    lastVisit = db.DateTimeProperty(auto_now_add=True)


class Posts(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    likes = db.IntegerProperty()
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    lastEdited = db.DateTimeProperty(auto_now_add=True)
    

class PostsHierarchy(db.Model):
    postID = db.IntegerProperty()
    child = db.IntegerProperty()


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        def valid_username(username):
            return USER_RE.match(username)

        def valid_password(password):
            return PASS_RE.match(password)

        def valid_mail(mail):
            if mail == "":
                return True
            return MAIL_RE.match(mail)

        def existing_username(username):
            query = "SELECT * FROM Users WHERE username = \'" + str(username) + "\'"
            a = db.GqlQuery(query)
            if not a.get():
                return False
            return True

        err_login = "Invalid username"
        err_login_exist = "Username already exist"
        err_password = "Invalid password"
        err_verify = "Passwords do not match"
        err_email = "Invalid e-mail"

        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if not valid_username(username):
            self.render("signup.html", username=username, email=email, err_login=err_login)
        elif existing_username(username):
            self.render("signup.html", username=username, email=email, err_login=err_login_exist)
        elif not valid_password(password):
            self.render("signup.html", username=username, email=email, err_password=err_password)
        elif not valid_mail(email):
            self.render("signup.html", username=username, email=email, err_email=err_email)
        elif password != verify:
            self.render("signup.html", username=username, email=email, err_verify=err_verify)
        else:
            pw_hash = make_pw_hash(username, password)
            a = Users(
                username=username,
                hashtext=pw_hash.split(',')[0],
                salt=pw_hash.split(',')[1],
                email=email
                )
            a.put()
            cookie = str(a.key().id()) + '|' + pw_hash.split(',')[0]
            self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % cookie)
            self.redirect("/blog/welcome")


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        def valid_username(username):
            return USER_RE.match(username)

        def valid_password(password):
            return PASS_RE.match(password)

        err_login = "Invalid username"
        err_password = "Invalid password"
        incorrect_login = "No such user. Try to sign up"
        incorrect_password = "Incorrect password"

        username = self.request.get("username")
        password = self.request.get("password")

        if not valid_username(username):
            self.render("login.html", username=username, err_login=err_login)
        elif not valid_password(password):
            self.render("login.html", username=username, err_password=err_password)
        else:
            query = "SELECT * FROM Users WHERE username = \'" + str(username) + "\'"
            a = db.GqlQuery(query)
            if not a.get():  # TODO is correct?
                self.render("login.html", username=username, err_login=incorrect_login)
            elif valid_pw(username, password, a.get().hashtext, a.get().salt):
                cookie = str(a.get().key().id()) + '|' + str(a.get().hashtext)
                self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % cookie)
                self.redirect("/blog/welcome")
            else:
                self.render("login.html", username=username, err_password=incorrect_password)


class SuccessPage(Handler):

    def get(self):

        cookie = self.request.cookies.get('login')
        if valid_cookie(cookie):
            user_id = cookie.split('|')[0]
            user = Users.get_by_id(int(user_id))
            if user.username:
                self.render("success.html", username=user.username)
            else:
                self.redirect("/blog/signup")
        else:
            self.redirect("/blog/signup")


class Logout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % '')
        self.redirect("/blog/signup")

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Posts ORDER BY created DESC limit 10")
        user = get_user_from_cookie(self)
        self.render("post.html", posts=posts, user=user)



class SinglePost(Handler):
    def get(self, product_id):
        user = get_user_from_cookie(self)
        self.render("post.html", posts=[Posts.get_by_id(int(product_id))], user=user, id=product_id)


class NewPost(Handler):
    #TODO: like, comment
    def get(self):
        user = get_user_from_cookie(self)
        self.render("newpost.html", user=user)

    def post(self):

        user = get_user_from_cookie(self)

        err_subject = "Error in subject"
        err_post = "Error in post"

        def valid(text):
            if len(text) > 0:
                return True
            else:
                return False

        subject = self.request.get("subject")
        content = self.request.get("content") # TODO: preserve \n for better formating opportunities

        parent = 0 #self.request.get("parent")

        if not valid(subject):
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                err_subject=err_subject,
                user=user
                )
        elif not valid(content):
            self.render("newpost.html", subject=subject, content=content, err_post=err_post, user=user)
        else:
            a = Posts(subject=subject, content=content, author=user, likes=0)
            a.put()
            b = PostsHierarchy(postID=parent, child=a.key().id())
            b.put()
            self.redirect("/blog/" + str(a.key().id()))

class NewComment(Handler):
    #TODO: like, comment
    def get(self):
        user = get_user_from_cookie(self)
        self.render("newpost.html", user=user)

    def post(self):
        pass #TODO
       
class EditPost(Handler):
    def get(self, product_id):
        user = get_user_from_cookie(self)
        if Posts.get_by_id(int(product_id)):
            post = Posts.get_by_id(int(product_id)) # TODO exception
            content = post.content
            subject = post.subject
            author = post.author
        if author == user:
            self.render("edit.html", user=user, content=content, subject=subject)
        else:
            self.redirect("/blog/login")  # TODO strange logic

    def post(self, product_id):

        user = get_user_from_cookie(self)

        err_subject = "Error in subject"
        err_post = "Error in post"

        def valid(text):
            if len(text) > 0:
                return True
            else:
                return False

        subject = self.request.get("subject")
        content = self.request.get("content")  # TODO: preserve \n for better formating opportunities

        if Posts.get_by_id(int(product_id)):
            post = Posts.get_by_id(int(product_id))
        else:
            self.redirect("/blog/login")  # TODO: strange logic

        if not valid(subject):
            self.render("edit.html", subject=subject, content=content, err_subject=err_subject, user=user)
        elif not valid(content):
            self.render("edit.html", subject=subject, content=content, err_post=err_post, user=user)
        else:
            post.content = content
            post.subject = subject
            post.lastEdited = datetime.datetime.now()
            post.put()
            self.redirect("/blog/" + str(product_id))


app = webapp2.WSGIApplication([
    ('/blog/signup', SignUp),
    ('/blog/welcome', SuccessPage),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog', MainPage),
    ('/blog/newpost', NewPost),
    (r'/blog/newpost/(\d+)', NewComment),
    (r'/blog/edit/(\d+)', EditPost),
    (r'/blog/(\d+)', SinglePost)
], debug=True)
