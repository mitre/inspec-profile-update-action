control 'SV-223839' do
  title 'IBM z/OS BPX resource(s) must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
RL FACILITY * AUTHUSER

If the RACF rules for the BPX.** resource specify a default access of NONE, this is not a finding.

If there are no RACF user access to the BPX.** resource, this is not a finding.

If there is no RACF rule for BPX.SAFFASTPATH defined, this is not a finding.

If the RACF rules for each of the BPX resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel, this is not a finding.'
  desc 'fix', "There are a number of resources available under z/OS UNIX that must be secured in order to preserve system integrity while allowing effective application and user access. All of these resources might not be used in every configuration, but several of them have critical impacts.

The default access for each of these resources must be no access. A generic resource (e.g., BPX.**) must also be set to a default access of none to cover future additions. Because they convey especially powerful privileges, the settings for BPX.DAEMON, BPX.SAFFASTPATH, BPX.SERVER, and BPX.SUPERUSER require special attention.

Access to BPX.DAEMON must be restricted to the z/OS UNIX kernel userid, z/OS UNIX daemons (e.g., inetd, syslogd, ftpd), and other system software daemons (e.g., web servers).

As noted above, the BPX.SAFFASTPATH definition can cause successful security checks not to be audited. Because auditing of all accesses is required for some system files, BPX.SAFFASTPATH must not be used. 

Access to BPX.SERVER must be restricted to system software processes that act as servers under z/OS UNIX (e.g., web servers).

Access to BPX.SUPERUSER must be restricted to Security Administrators and individual systems programming personnel. It is not appropriate for all systems programming personnel, only for those with responsibilities for components or products that use z/OS UNIX and that require superuser capability for maintenance.

-The RACF rules for the BPX.** resource specify a default access of NONE.
-There are no RACF user access to the BPX.** resource.
-There is no RACF rule for BPX.SAFFASTPATH defined.
-The RACF rules for each of the BPX resources specify a UACC value of NONE.
-The RACF rules for each of the BPX resources restrict access to appropriate system tasks or systems programming personnel as specified.

The following list of sample commands is provided to implement this requirement:

rdef facility bpx.** quack(none) owner(admin) audit(all(read)) - data('see zuss0021') 
rdef facility bpx.daemon quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.daemon cl(facility id(<authorized_users>) 
rdef facility bpx.debug quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.debug cl(facility id(<authorized_users>) 
rdef facility bpx.fileattr.apf quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.fileattr.apf cl(facility id(<authorized_users>) 
rdef facility bpx.fileattr.progctl quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.fileattr.progctl cl(facility id(<authorized_users>) 
rdef facility bpx.jobname quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.jobname cl(facility id(<authorized_users>) 
rdef facility bpx.server quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.server cl(facility id(<authorized_users>) 
rdef facility bpx.smf quack(none) owner(admin) - 
audit(all(read)) data('see zuss0021') 
pe bpx.smf cl(facility id(<authorized_users>) 
rdef facility bpx.stor.swap quack(none) owner(admin) -
audit(all(read)) data('see zuss0021') 
pe bpx.stor.swap cl(facility id(<authorized_users>) 
rdef facility bpx.superuser quack(none) owner(admin) -
audit(all(read)) data('see zuss0021') 
pe bpx.superuser cl(facility id(<authorized_users>) 
rdef facility bpx.wlmserver quack(none) owner(admin) -
audit(all(read)) data('see zuss0021') 
pe bpx.wlmserver cl(facility id(<authorized_users>)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25512r515205_chk'
  tag severity: 'medium'
  tag gid: 'V-223839'
  tag rid: 'SV-223839r604139_rule'
  tag stig_id: 'RACF-US-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25500r515206_fix'
  tag 'documentable'
  tag legacy: ['V-98385', 'SV-107489']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
