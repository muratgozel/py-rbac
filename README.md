# py-rbac
Python implementation of the NIST model for role based access control (RBAC).

[The NIST model][95961bd8] proposes four level of role based access control implementation:
1. **Flat**
- users acquire permissions through roles
- must support many-to-many user-role assignment
- must support many-to-many permission-role assignment
- must support user-role assignment review
- users can use permissions of multiple roles simultaneously
2. **Hierarchical**
- Flat +
- must support role hierarchy (partial order)
- arbitrary hierarchies
- limited hierarchies
3. **Constrained**
- Hierarchical +
- must enforce separation of duties (SOD)
- arbitrary hierarchies
- limited hierarchies
4. **Symmetric**
- Constrained +
- must support permission-role review with performance effectively comparable to user-role review
- arbitrary hierarchies
- limited hierarchies

This library supports Level 1, 2 and 3.

## Usage
I've tried to explain the usage based on levels but the library is flexible enough to
use any feature freely without thinking about levels.

### Install
Through pip:
```sh
pip install py-rbac
```

### Flat Scenario
This is the simplest scenario an mostly used I think. Let's configure it first:
```py
from rbac import RBAC

rbac = RBAC()

# a role for junior editors
jr_editor = rbac.create_role('jr_editor')

# a domain or resource is also an object
article = rbac.create_domain('article')

# create permissions
create = rbac.create_permission('c')
read = rbac.create_permission('r')
update = rbac.create_permission('u')
delete = rbac.create_permission('d')

# give junior a read permission for articles
jr_editor.add_permission(read, article)

# lets create a subject. a user or a third party client
subject = rbac.create_subject('some_int_or_str')

# our subject is new in the job
subject.authorize(jr_editor)

# lock rbac configuration
# this validates the entire structure of our configuration
# will sense more meaning as we use advanced features below
rbac.lock()
```
After your application executed some code and is about respond client's request:
```py
# check if the client is allowed to...
rbac.go('some_int_or_str', article, create)
# this will raise an exception since we didn't give a create permission to our junior
# raised RBACAuthorizationError
```

### Hierarchical Scenario
In this example, there are hierarchical relationships between roles. Each role
inherits its children roles and permissions. (Inheriting can be disabled but
review this scenario first.) Configure and lock as always:
```py
from rbac import RBAC

rbac = RBAC()

jr_editor = rbac.create_role('jr_editor')
editor = rbac.create_role('editor', children=jr_editor)
it = rbac.create_role('it', children=(jr_editor, editor))

article = rbac.create_domain('article')
service_conf = rbac.create_domain('service_conf')

create = rbac.create_permission('c')
read = rbac.create_permission('r')
update = rbac.create_permission('u')
delete = rbac.create_permission('d')

jr_editor.add_permission(read, article)
editor.add_permission(create, article)
it.add_permission((create, read, update, delete), service_conf)

john = rbac.create_subject(1)
john.authorize(jr_editor)
jack = rbac.create_subject(2)
jack.authorize(editor)
mark = rbac.create_subject(3)
mark.authorize(it)

rbac.lock()
```
Run:
```py
assert rbac.go(2, article, read) is None
assert rbac.go(1, article, read) is None
assert rbac.go(3, article, create) is None
assert rbac.go(3, service_conf, create) is None

# will raise
try:
  rbac.go(1, article, create)
except RBACAuthorizationError as e:
  raise
```
### Constrained Scenario
In this scenario, there are constraints. Constraints restricts the authorization
flow as they are being applied through RBAC objects. Configure and lock:
```py
from rbac import RBAC

# an article from our application! we use this as our domain
class Article():
  """docstring for Article."""

  def __init__(self, id, author):
    self.id = id
    self.author = author

rbac = RBAC()

# we can only allow one person to be assigned to this role
jr_editor = rbac.create_role('jr_editor', max_subjects=1)
# we may have editors up to 10
editor = rbac.create_role('editor', children=jr_editor, max_subjects=10)
# a chief role for one person but it won't inherit its children permissions
chief = rbac.create_role('chief', children=(jr_editor, editor), inherit=False, max_subjects=1)

# we use Article object as input to our RBACDomain but why an object?
# specifically for the match_domain_prop constraint.
article = rbac.create_domain(Article)

# as usual
create = rbac.create_permission('c')
read = rbac.create_permission('r')
update = rbac.create_permission('u')
delete = rbac.create_permission('d')

# our junior can read and create articles...
jr_editor.add_permission((create, read), article)
# ... but can only remove the ones which he/she wrote
# match_domain_prop constraint indicates that the article instance property
# "author" should match with the at-then id of the subject.
jr_editor.add_permission(delete, article, match_domain_prop='author')
editor.add_permission(create, article)

# defining 2 jrs... hmmm
john = rbac.create_subject(1)
john.authorize(jr_editor)
another_john = rbac.create_subject(2)
another_john.authorize(jr_editor)

# this will raise because our jr role can have 1 jrs max.
try:
  rbac.lock()
except RBACConfigurationError as e:
  raise

# ok then, fire another_john!
another_john.revoke(rbac.get_role_by_name('jr_editor'))

# now locked.
assert rbac.lock() is None

# or unblock and add 2 more subject:
rbac.unlock()
jack = rbac.create_subject(3)
jack.authorize(editor)
brad = rbac.create_subject(4)
brad.authorize(chief)

rbac.lock()
```
Our API received a request about deleting some article:
```py
some_article = Article(28372, 1)
# our junior john trying to delete an article
# the library will match the john's id which is 1 with the article's author and
# allow the operation if they match.
assert rbac.go(1, some_article, delete) is None
```

## Versioning
This library uses calendar versioning.

  [95961bd8]: https://csrc.nist.gov/CSRC/media/Publications/conference-paper/2000/07/26/the-nist-model-for-role-based-access-control-towards-a-unified-/documents/sandhu-ferraiolo-kuhn-00.pdf "The NIST model for role based access control"

## Contribution
This project uses pipenv to manage its dependencies. The only dependency it has
is the pytest package which is used in development.

1. Clone the repository.
2. Run `pipenv install`
3. Make updates.
4. Run `pytest` under `pipenv shell`
5. Run `git push origin master` and create a pull request.
