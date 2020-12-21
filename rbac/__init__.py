class RBACError(Exception):
  """docstring for RBACError."""
  pass

class RBACConfigurationError(RBACError):
  """docstring for RBACConfigurationError."""

  def __init__(self, msg):
    self.msg = msg

class RBACAuthorizationError(RBACError):
  """docstring for RBACAuthorizationError."""

  def __init__(self, msg):
    self.msg = msg

class RBACDomain():
  """docstring for RBACDomain."""

  def __init__(self, value):
    self.value = value
    name = self.value.__class__.__name__
    self.name = value if name == 'str' else value.__name__ if name == 'type' else name

class RBACPermission():
  """docstring for RBACPermission."""

  def __init__(self, name):
    self.name = name

class PermissionAggregate():
  """docstring for PermissionAggregate."""

  def __init__(self, permission: RBACPermission, domain: RBACDomain, match_domain_prop=None):
    self.permission = permission
    self.domain = domain
    self.match_domain_prop = match_domain_prop

class RBACRole():
  """docstring for RBACRole."""

  properties = (
    'children',
    'inherit',
    'max_subjects',
    'max_permissions'
  )

  def __init__(self, name, d):
    for k in self.properties:
      setattr(self, k, None)

    for k, v in d.items():
      if k in self.properties:
        if k == 'children' and v is not None:
          if type(v) is not list and type(v) is not tuple and not isinstance(v, RBACRole):
            raise RBACConfigurationError('Children can be an instance of RBACRole or a list of RBACRoles')
          children = [v] if isinstance(v, RBACRole) else v
          setattr(self, k, children)
        else:
          setattr(self, k, v)

    self.name = name
    self.permission_aggregates = []

  def add_permission(self, permission: RBACPermission, domain: RBACDomain, match_domain_prop=None):
    if type(permission) is list or type(permission) is tuple:
      for p in permission:
        self.add_permission(p, domain, match_domain_prop)
      return

    if type(domain) is list or type(domain) is tuple:
      for d in domain:
        self.add_permission(permission, d, match_domain_prop)
      return

    if not isinstance(permission, RBACPermission):
      raise RBACConfigurationError('Invalid permission object.')

    aggregate = PermissionAggregate(permission, domain, match_domain_prop)

    self.permission_aggregates.append(aggregate)

class RBACSubject():
  """docstring for RBACSubject."""

  def __init__(self, identifier, max_roles=None):
    self.identifier = identifier
    self.max_roles = max_roles
    self.authorizations = []

  def authorize(self, role: RBACRole):
    if not isinstance(role, RBACRole):
      raise RBACConfigurationError('The argument "role" should be a RBACRole object.')

    self.authorizations.append(role)

  def revoke(self, role: RBACRole):
    authorizations = []
    for r in self.authorizations:
      if r.name != role.name:
        authorizations.append(r)
    self.authorizations = authorizations

class RBAC():
  """docstring for RBAC."""

  def __init__(self):
    self._roles = []
    self._subjects = []
    self._domains = []
    self._permissions = []
    self._state = 'OPEN'

  def create_role(self, name, **kwargs):
    if self.is_locked():
      raise RBACConfigurationError('RBAC is locked.')

    r = RBACRole(name, kwargs)
    self._roles.append(r)
    return r

  def create_domain(self, domain: any):
    if self.is_locked():
      raise RBACConfigurationError('RBAC is locked.')

    d = RBACDomain(domain)
    self._domains.append(d)
    return d

  def create_permission(self, name):
    if self.is_locked():
      raise RBACConfigurationError('RBAC is locked.')

    p = RBACPermission(name)
    self._permissions.append(p)
    return p

  def create_subject(self, identifier, max_roles=None):
    if self.is_locked():
      raise RBACConfigurationError('RBAC is locked.')

    s = RBACSubject(identifier, max_roles)
    self._subjects.append(s)
    return s

  def get_role_by_name(self, name):
    for r in self._roles:
      if r.name == name:
        return r

  def get_subject_by_id(self, id):
    for s in self._subjects:
      if s.identifier == id:
        return s

  def get_role_family(self, role, recursive_calls=0):
    if recursive_calls > 1000:
      raise RBACConfigurationError('Possible inifinte loop. Please check the hierarchy of the roles.')

    result = []
    if role.children is not None and role.inherit is not False:
      for c in role.children:
        result = result + [c] + self.get_role_family(c, recursive_calls+1)

    return result

  def lock(self):
    self.validate()
    self._state = 'LOCKED'

  def is_locked(self):
    return True if self._state == 'LOCKED' else False

  def unlock(self):
    self._state = 'OPEN'

  def validate(self):
    # validate roles constraints
    for r in self._roles:
      if r.max_subjects is not None:
        count_subjects = 0
        for s in self._subjects:
          if r in s.authorizations:
            count_subjects += 1
        if count_subjects > r.max_subjects:
          raise RBACConfigurationError(f'The role "{r.name}" can not have more than {r.max_subjects} subjects.')

      if r.max_permissions is not None:
        if len(r.permission_aggregates) > r.max_permissions:
          raise RBACConfigurationError(f'The role "{r.name}" can not have more than {r.max_permissions} permissions.')

    # validate subject constraints
    for s in self._subjects:
      if s.max_roles is not None:
        count_roles = len(s.authorizations)
        if count_roles > s.max_roles:
          raise RBACConfigurationError(f'The subject "{s.identifier}" can not have more than {s.max_roles} roles.')

  def go(self, subject: RBACSubject, domain: RBACDomain, permission: RBACPermission):
    if self.is_locked() is False:
      raise RBACAuthorizationError('RBAC is not in the lock mode.')

    subject_id = subject if not isinstance(subject, RBACSubject) else subject.identifier
    verified_subject = None
    for s in self._subjects:
      if getattr(s, 'identifier') == subject_id:
        verified_subject = s
    if verified_subject is None:
      raise RBACAuthorizationError('Unrecognized subject.')

    domain_name = domain if not isinstance(domain, RBACDomain) else domain.name
    verified_domain = None
    for d in self._domains:
      if getattr(d, 'name') == domain_name:
        verified_domain = d
      elif type(d.value) == type and isinstance(domain, d.value):
        verified_domain = d
    if verified_domain is None:
      raise RBACAuthorizationError('Unrecognized domain.')

    permission_name = permission if not isinstance(permission, RBACPermission) else permission.name
    verified_permission = None
    for p in self._permissions:
      if getattr(p, 'name') == permission_name:
        verified_permission = p
    if verified_permission is None:
      raise RBACAuthorizationError('Unrecognized permission.')

    subject_roles = verified_subject.authorizations
    if len(subject_roles) == 0:
      raise RBACAuthorizationError('Subject has no role.')
    subject_roles_family = [] + subject_roles
    for r in subject_roles:
      subject_roles_family = subject_roles_family + self.get_role_family(r)
    subject_roles_family_filtered = []
    for r in subject_roles_family:
      duplicate = False
      for rf in subject_roles_family_filtered:
        if rf.name == r.name:
          duplicate = True
          break
      if duplicate is False:
        subject_roles_family_filtered.append(r)

    match = False
    for r in subject_roles_family_filtered:
      permission_aggregates = r.permission_aggregates
      if len(permission_aggregates) == 0:
        continue

      for pa in permission_aggregates:
        if pa.domain.name == verified_domain.name and pa.permission.name == verified_permission.name:
          if pa.match_domain_prop is not None:
            if verified_subject.identifier == getattr(domain, pa.match_domain_prop):
              match = True
            else:
              match = False
          else:
            match = True
          break

      if match is True:
        break

    if match is False:
      raise RBACAuthorizationError('Not authorized.')
