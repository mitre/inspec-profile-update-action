control 'SV-99165' do
  title 'NIS/NIS+/yp files must be owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security. Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration, which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file ownership:

# ls -la /var/yp/*

If the NIS file ownership is not "root", sys, or bin, this is a finding.'
  desc 'fix', 'Change the ownership of NIS/NIS+/yp files to "root", "sys", "bin", or "system". Consult vendor documentation to determine the location of the files:

# chown root <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88207r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88515'
  tag rid: 'SV-99165r1_rule'
  tag stig_id: 'VROM-SL-000515'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
