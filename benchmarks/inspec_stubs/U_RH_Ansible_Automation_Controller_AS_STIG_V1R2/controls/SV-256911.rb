control 'SV-256911' do
  title 'Automation Controller must install security-relevant software updates within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security relevant software updates must be installed within the timeframes directed by an authoritative source in order to maintain the integrity and confidentiality of the system and its organizational assets.'
  desc 'check', 'As a system administrator for each Automation Controller host inspect the status of the DNF Automatic timer:

systemctl status dnf-automatic.timer

If "Active: active" is not included in the output, this is a finding.

Inspect the configuration of DNF Automatic:

 grep apply_updates /etc/dnf/automatic.conf

If "apply_updates = yes" is not displayed, this is a finding.'
  desc 'fix', 'Install and enable DNF Automatic:

dnf install dnf-automatic
(run the install)
systemctl enable --now dnf-automatic.timer

Modify /etc/dnf/automatic.conf and set "apply_updates = yes".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60586r902301_chk'
  tag severity: 'medium'
  tag gid: 'V-256911'
  tag rid: 'SV-256911r902303_rule'
  tag stig_id: 'APAS-AT-000122'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-60528r902302_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
