control 'SV-16801' do
  title 'Patches and security updates are not current on the VirtualCenter Server.'
  desc 'Organizations need to stay current with all applicable VirtualCenter Server software updates that are released from VMware.  If updates and patches are not installed, then security vulnerabilities may be open. Open vulnerabilities may provide an access point for an attacker to use to gain access to the system.'
  desc 'check', 'Go to the VirtualCenter Server and perform the following.
1. Login to the VirtualCenter Server with the VI Client.
2. At the top of the menu select Help>About Virtual Infrastructure.
3. Review the Virtual Infrastructure Version and Build number and compare it the latest patches listed below.  If Internet access is available, the reviewer should check for the latest patches on VMware’s website to verify the VirtualCenter patches have not been updated recently.  The website location is http://www.vmware.com/download/vi/.  If the version build number is older than the listed ones below, this is a finding.  If the version is not listed or is older than version 2.0.1, this is a finding as well.

VMware VirtualCenter 2.5
Latest Version: 2.5 | 7/10/2009 | Build:174768 

VMware VirtualCenter 2.0.2 Update 3
Version: 2.0.2 Update 3 | 2/15/2008 | Build: 75762

VMware VirtualCenter 2.0.2 Update 2
Version: 2.0.2 Update 2 | 11/8/2007 | Build: 62327

VMware VirtualCenter 2.0.2 Update 1
Version: 2.0.2 Update 1 | 10/29/2007 | Build: 61426 – End of support 11/08/2008

VMware VirtualCenter 2.0.2
Version: 2.0.2 | 7/19/2007 | Build: 50618 – End of support 10/29/2008

VMware VirtualCenter 2.0.1
Version: 2.0.1 | 10/02/2006 | Build: 32042 – End of support 7/19/2008'
  desc 'fix', 'Apply all the latest patches to VirtualCenter.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15860'
  tag rid: 'SV-16801r1_rule'
  tag stig_id: 'ESX0610'
  tag gtitle: 'Patches and security updates are not current.'
  tag fix_id: 'F-15820r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
