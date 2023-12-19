control 'SV-46363' do
  title 'Programs and features not necessary for operations must be removed.'
  desc 'Just as running unneeded services and protocols increase the attack surface of the web server, running unneeded utilities and programs is also an added risk to the web server.'
  desc 'check', 'Review programs installed on the OS.
1. Open Control Panel.
2. Open Programs and Features.
3. The following programs may be installed without any additional documentation:
  Administration Pack for IIS 7.0
  IIS Search Engine Optimization Toolkit
  Microsoft .NET Framework version 3.5 SP1 or greater
  Microsoft Web Platform Installer version 3.x or greater
  Virtual Machine Additions
4. Review the installed programs, if any programs are installed other than those listed above, this is a finding.

NOTE: If additional software is needed and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', 'Remove all unapproved programs and roles from the production web server.'
  impact 0.3
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32932r4_chk'
  tag severity: 'low'
  tag gid: 'V-2251'
  tag rid: 'SV-46363r3_rule'
  tag stig_id: 'WG130 IIS7'
  tag gtitle: 'WG130'
  tag fix_id: 'F-29063r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
