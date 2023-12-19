control 'SV-219159' do
  title 'The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the Ubuntu operating system may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Check that the "mcafeetp" package has been installed:

# dpkg -l | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Check that the daemon is running:

# /opt/McAfee/ens/tp/init/mfetpd-control.sh status

If the daemon is not running, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to use ENSLTP.

Install the mcafeetp package via the ePO server.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20884r858513_chk'
  tag severity: 'medium'
  tag gid: 'V-219159'
  tag rid: 'SV-219159r858515_rule'
  tag stig_id: 'UBTU-18-010021'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-20883r858514_fix'
  tag 'documentable'
  tag legacy: ['SV-109649', 'V-100545']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
