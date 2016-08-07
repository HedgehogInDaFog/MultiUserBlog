from google.appengine.ext import db


class Users(db.Model):
    username = db.StringProperty()
    hashtext = db.StringProperty()
    salt = db.StringProperty()
    email = db.StringProperty()


class Posts(db.Model):
    '''
    Non obvious parameters:
    likes - number of likes for post/comment
    level - level in the hierarchy of posts. i.e. level=0 for post,
        level=1 for a comment to a post, level=2 for a comment to a
        level-1 comment, etc.
    rootID - for posts rootID=0, for comments rootID = ID of the post.
    So all level comments for the post will have same rootID
    '''
    subject = db.StringProperty()
    content = db.TextProperty()
    likes = db.IntegerProperty()
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_edited = db.DateTimeProperty(auto_now_add=True)
    level = db.IntegerProperty()
    rootID = db.IntegerProperty()


class PostsHierarchy(db.Model):
    postID = db.IntegerProperty()
    child = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    postID = db.IntegerProperty()
    userID = db.IntegerProperty()
