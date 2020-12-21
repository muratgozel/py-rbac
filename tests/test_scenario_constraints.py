import pytest
from rbac import RBAC, RBACConfigurationError, RBACAuthorizationError

def test_scenario_constraints():
  class Article():
    """docstring for Article."""

    def __init__(self, id, author):
      self.id = id
      self.author = author

  rbac = RBAC()

  jr_editor = rbac.create_role('jr_editor', max_subjects=1)
  editor = rbac.create_role('editor', children=jr_editor, max_subjects=10)
  chief = rbac.create_role('chief', children=(jr_editor, editor), inherit=False, max_subjects=1)

  article = rbac.create_domain(Article)

  create = rbac.create_permission('c')
  read = rbac.create_permission('r')
  update = rbac.create_permission('u')
  delete = rbac.create_permission('d')

  jr_editor.add_permission(read, article)
  jr_editor.add_permission(delete, article, match_domain_prop='author')
  editor.add_permission(create, article)

  john = rbac.create_subject(1)
  john.authorize(jr_editor)
  another_john = rbac.create_subject(2)
  another_john.authorize(jr_editor)

  with pytest.raises(RBACConfigurationError):
    rbac.lock()

  another_john.revoke(rbac.get_role_by_name('jr_editor'))

  assert rbac.lock() is None

  rbac.unlock()

  jack = rbac.create_subject(3)
  jack.authorize(editor)
  brad = rbac.create_subject(4)
  brad.authorize(chief)

  rbac.lock()

  some_article = Article(28372, 1)

  assert rbac.go(1, some_article, delete) is None
