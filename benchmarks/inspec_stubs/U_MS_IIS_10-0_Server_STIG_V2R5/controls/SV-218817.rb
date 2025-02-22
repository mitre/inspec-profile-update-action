control 'SV-218817' do
  title 'The IIS 10.0 web server must not be running on a system providing any other role.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The web server must provide the capability to disable or deactivate network-related services deemed non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.'
  desc 'check', 'Review programs installed on the OS.

Open Control Panel.

Open Programs and Features.

The following programs may be installed without any additional documentation:

Administration Pack for IIS
IIS Search Engine Optimization Toolkit
Microsoft .NET Framework version 3.5 SP1 or greater
Microsoft Web Platform Installer version 3.x or greater
Virtual Machine Additions

Review the installed programs, if any programs are installed other than those listed above, this is a finding.

Note: If additional software is needed and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', 'Remove all unapproved programs and roles from the production web server.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20289r310926_chk'
  tag severity: 'medium'
  tag gid: 'V-218817'
  tag rid: 'SV-218817r561041_rule'
  tag stig_id: 'IIST-SV-000148'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-20287r310927_fix'
  tag 'documentable'
  tag legacy: ['SV-109273', 'V-100169']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
