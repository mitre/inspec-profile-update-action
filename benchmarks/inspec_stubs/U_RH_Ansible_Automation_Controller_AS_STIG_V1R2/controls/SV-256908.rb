control 'SV-256908' do
  title 'Automation Controller must use cryptographic mechanisms to protect the integrity of log tools.'
  desc 'Protecting the integrity of the tools used for logging purposes is a critical step in ensuring the integrity of log data. Log data includes all information (e.g., log records, log settings, and log reports) needed to successfully log information system activity.

It is not uncommon for attackers to replace the log tools or inject code into the existing tools for the purpose of providing the capability to hide or erase system activity from the logs.

To address this risk, log tools must be cryptographically signed in order to provide the capability to identify when the log tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.

Automation Controller server log tools must use cryptographic mechanisms to protect the integrity of the tools or allow cryptographic protection mechanisms to be applied to their tools.'
  desc 'check', 'As an administrator, log in to each Automation Controller host.

Verify the correct Red Hat RPM signing key is available on each host by listing the keys using the following command:

rpm -qa gpg-pubkey*

Manually inspect against publicly listed keys on https://www.redhat.com. If the keys do not match, this is a finding.

Import the key using the following command:

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

Verify the signatures of installed RPMs necessary for Automation Controller:

For RPM in $(rpm -qa); do rpm -K --nosignature ${RPM} | grep "NOT OK" && return 1; done ; echo "FAILED"

If this outputs "FAILED", this is a finding.'
  desc 'fix', 'The administrator must reinstall all Automation Controller hosts and Automation Controller.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60583r902292_chk'
  tag severity: 'medium'
  tag gid: 'V-256908'
  tag rid: 'SV-256908r902294_rule'
  tag stig_id: 'APAS-AT-000078'
  tag gtitle: 'SRG-APP-000290-AS-000174'
  tag fix_id: 'F-60525r902293_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
