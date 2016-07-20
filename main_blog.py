import jinja2
import os
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


class Posts(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Posts ORDER BY created DESC limit 10")
        self.render("post.html", posts=posts)


class SinglePost(Handler):
    def get(self, product_id):
        self.render("post.html", posts=[Posts.get_by_id(int(product_id))])


class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):

        err_subject = "Error in subject!"
        err_post = "Error in post!"

        def valid(text):
            if len(text) > 0:
                return True
            else:
                return False

        subject = self.request.get("subject")
        content = self.request.get("content")

        if not valid(subject):
            self.render("newpost.html", subject=subject, content=content, err_subject=err_subject)
        elif not valid(content):
            self.render("newpost.html", subject=subject, content=content, err_post=err_post)
        else:
            a = Posts(subject=subject, content=content)
            a.put()
            self.redirect("/blog/" + str(a.key().id()))


app = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/newpost', NewPost),
    (r'/blog/(\d+)', SinglePost)
], debug=True)
