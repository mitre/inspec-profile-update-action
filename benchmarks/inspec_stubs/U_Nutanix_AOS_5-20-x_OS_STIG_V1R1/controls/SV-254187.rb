control 'SV-254187' do
  title 'Nutanix AOS must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools.

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

Verify the location of the seven auditing tools that require cryptographic protection with the following command:
(auditctl, auditd, ausearch, aureport, autrace, augenrules, rsyslogd)

$ sudo ls -al /usr/sbin/ | egrep '(audit|au|rsys)'

If the seven identified audit tools are not listed, this is a finding.

Check the aide.conf file for the  configured rule set.

$ sudo grep -i "FIPSR =" /etc/aide.conf  
FIPSR = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha512

If the FIPSR rule set is commented out or does not display, this is a finding.

Check to ensure that the root directory of the seven audit tools is configured to be monitored and that the proper rule set is applied to that directory (/usr/).

$ sudo grep -i /usr /etc/aide.conf
/usr    FIPSR

if the /usr directory is not listed or  has a preceding '=' or '!' sign or the Rule  Set is not set to FIPSR, this is a finding.)
  desc 'fix', 'Configure AIDE on Nutanix AOS by running the following command:

$ ncli cluster edit-cvm-security-params enable-aide=true'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57672r846647_chk'
  tag severity: 'high'
  tag gid: 'V-254187'
  tag rid: 'SV-254187r846649_rule'
  tag stig_id: 'NUTX-OS-000990'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-57623r846648_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
