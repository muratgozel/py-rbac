import pytest
from rbac import RBAC, RBACConfigurationError, RBACAuthorizationError

def test_scenario_hierarchy():
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

  assert rbac.go(2, article, read) is None
  assert rbac.go(1, article, read) is None
  assert rbac.go(3, article, create) is None
  assert rbac.go(3, service_conf, create) is None

  with pytest.raises(RBACAuthorizationError):
    rbac.go(1, article, create)
