import pytest
from rbac import RBAC, RBACConfigurationError, RBACAuthorizationError

def test_scenario_flat():
  rbac = RBAC()
  assert isinstance(rbac, RBAC) == True

  jr_editor = rbac.create_role('jr_editor')
  assert jr_editor.name == 'jr_editor'
  assert jr_editor.children == None

  article = rbac.create_domain('article')
  assert article.name == 'article'

  create = rbac.create_permission('c')
  assert create.name == 'c'
  read = rbac.create_permission('r')
  update = rbac.create_permission('u')
  delete = rbac.create_permission('d')

  jr_editor.add_permission(create, article)
  jr_editor.add_permission(read, article)

  subject = rbac.create_subject('some_int_or_str')
  assert subject.identifier == 'some_int_or_str'
  subject.authorize(jr_editor)

  with pytest.raises(RBACAuthorizationError):
    rbac.go('some_int_or_str', article, 'u')

  with pytest.raises(RBACAuthorizationError):
    rbac.go('some_int_or_str', article, create)

  rbac.lock()

  assert rbac.go('some_int_or_str', article, create) is None
