import jinja2
import os
import webapp2
import re
import random
import string
import hashlib
import datetime
import time

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
        if user:
            if user.username:
                return str(user.username)
            else:
                return "Anonymous"
        else:
            return "Anonymous"
    else:
        return "Anonymous"


def get_user_id_from_cookie(self):
    cookie = self.request.cookies.get('login')
    if valid_cookie(cookie):
        return int(cookie.split('|')[0])
    else:
        return None


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
    level = db.IntegerProperty()
    rootID = db.IntegerProperty()


class PostsHierarchy(db.Model):
    postID = db.IntegerProperty()
    child = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    postID = db.IntegerProperty()
    userID = db.IntegerProperty()


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


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


class Logout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'login=%s; Path=/' % '')
        self.redirect("/blog/signup")

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



class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Posts WHERE level = 0 ORDER BY created DESC limit 10")
        user = get_user_from_cookie(self)
        self.render("post.html", posts=posts, user=user)


class SinglePost(Handler):
    def get(self, product_id):
        def get_comments_tree(root_post_id):

            def get_next_level(curr_id):
                next_level = []
                query = "SELECT child FROM PostsHierarchy WHERE postID = " + str(curr_id) + " ORDER BY created"
                children_id = db.GqlQuery(query)
                for i in range(children_id.count()):
                    tmp = children_id.get(offset=i).child
                    next_level.append(Posts.get_by_id(int(tmp)))
                return next_level

            def dfs(v):
                visited.append(v)
                children = get_next_level(v)
                for w in children:
                    if w.key().id() not in visited:
                        comments.append(w)
                        dfs(w.key().id())

            visited = []
            comments = []
            dfs(root_post_id)
            return comments


        user = get_user_from_cookie(self)
        comments = get_comments_tree(product_id)

        self.render("singlepost.html", post=Posts.get_by_id(int(product_id)), user=user, id=product_id, comments_count=len(comments), comments=comments)


class NewRecord(Handler):
    def get(self, product_id=0):
        user = get_user_from_cookie(self)
        self.render("newpost.html", user=user, product_id=product_id)

    def post(self, product_id=0):

        def valid(text):
            if len(text) > 0:
                return True
            else:
                return False

        user = get_user_from_cookie(self)

        err_subject = "Error in subject"
        err_post = "Error in post"

        if int(product_id) == 0:
            subject = self.request.get("subject")
            level = 0
            rootID = 0
        else:
            subject = " "
            post = Posts.get_by_id(int(product_id))
            level = post.level + 1
            if post.level == 0:
                rootID = int(product_id)
            else:
                rootID = post.rootID
        content = self.request.get("content")  # TODO: preserve \n for better formating opportunities

        if not valid(subject):
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                err_subject=err_subject,
                user=user,
                product_id=product_id
            )
        elif not valid(content):
            self.render("newpost.html", subject=subject, content=content, err_post=err_post, user=user, product_id=product_id)
        else:
            a = Posts(subject=subject, content=content, author=user, likes=0, level=level, rootID=rootID)
            a.put()
            b = PostsHierarchy(postID=int(product_id), child=a.key().id())
            b.put()
            time.sleep(0.2)
            if int(product_id) == 0:
                self.redirect("/blog/" + str(a.key().id()))
            else:
                self.redirect("/blog/" + str(rootID))


class NewPost(NewRecord):
    pass


class NewComment(NewRecord):
    pass


class EditPost(Handler):
    def get(self, product_id):
        user = get_user_from_cookie(self)
        if Posts.get_by_id(int(product_id)):
            post = Posts.get_by_id(int(product_id))  # TODO exception
            content = post.content
            subject = post.subject
            author = post.author
            if int(post.rootID) == 0:
                isComment = 0
            else:
                isComment = 1
        if author == user:
            self.render("edit.html", user=user, content=content, subject=subject, isComment=isComment, product_id=product_id)
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

        if int(post.rootID) == 0:
            isComment = 0
        else:
            isComment = 1

        if (isComment == 0) and (not valid(subject)):
            self.render("edit.html", subject=subject, content=content, err_subject=err_subject, user=user, product_id=product_id, isComment=isComment)
        elif not valid(content):
            self.render("edit.html", subject=subject, content=content, err_post=err_post, user=user, product_id=product_id, isComment=isComment)
        else:
            post.content = content
            post.subject = subject
            post.lastEdited = datetime.datetime.now()
            post.put()
            if int(post.rootID) != 0:
                self.redirect("/blog/" + str(post.rootID))
            else:
                self.redirect("/blog/" + str(product_id))

class Like(Handler):
    def get(self, product_id):
        userID = get_user_id_from_cookie(self)
        user = get_user_from_cookie(self)
        query = "SELECT * FROM Likes WHERE postID = " + str(product_id) + " AND userID = " + str(userID)
        likes = db.GqlQuery(query)
        post = Posts.get_by_id(int(product_id))
        if likes.count() == 0 and post.author != user:
            a = Likes(postID=int(product_id), userID=userID)
            post.likes += 1
            post.put()
            a.put()
        if post.rootID != 0:
            self.redirect("/blog/" + str(post.rootID))
        else:
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
    (r'/blog/(\d+)', SinglePost),
    (r'/blog/like/(\d+)', Like)
], debug=True)
