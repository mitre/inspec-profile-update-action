control 'SV-248810' do
  title 'OL 8 must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 
 
Audit tools include but are not limited to vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators. 
 
It is not uncommon for attackers to replace the audit tools or inject code into the existing tools to provide the capability to hide or erase system activity from the audit logs. 
 
To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools. 
 
Check the selection lines to ensure AIDE is configured to add/check with the following command: 
 
     $ sudo grep -E '(\\/usr\\/sbin\\/(audit|au|rsys))' /etc/aide.conf 
 
     /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512 
     /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512 
 
If any of the audit tools listed above do not have an appropriate selection line, this is a finding."
  desc 'fix', 'Add or update the following lines to "/etc/aide.conf" to protect the integrity of the audit tools. 
 
# Audit Tools 
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512 
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52244r880558_chk'
  tag severity: 'medium'
  tag gid: 'V-248810'
  tag rid: 'SV-248810r880559_rule'
  tag stig_id: 'OL08-00-030650'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-52198r833240_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
