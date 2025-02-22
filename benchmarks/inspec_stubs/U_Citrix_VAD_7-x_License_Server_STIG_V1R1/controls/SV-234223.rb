control 'SV-234223' do
  title 'Citrix License Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
  desc 'check', 'Identify all License Server administrators as the appropriate Active Directory domain/user or domain/group account.

1. Log on to the License Server with an administrator account.

2. To open the License Administration Console on the computer on which it is installed: Start menu, choose All Programs >> Citrix >> License Administration Console.

3. To open the console on a remote server or cluster, navigate the browser to one of the following URL options:

a. Caution-https://License server name:Web service port

b. Caution-https://Client access point name:Web service port

c. Caution-https://IP:Web service port

4. In the top right corner of the console, select Administration.

5. Select >> Settings >> Accounts.

6. Identify all License Server administrators as the appropriate Active Directory domain/user or domain/group account.

If the desired License Server administrator account is not returned, this is a finding.'
  desc 'fix', 'A default administrator account is created during the installation of the License Administration Console. Use the administrator account to first log on to the console and then configure more users. For Active Directory installations, domain\\InstallUser** and BUILTIN\\Administrators are added.

1. In the top right corner of the console, select Administration.

2. Select >> Settings >> Accounts.

3. Under User Administration, select Add to add appropriate domain users and groups.

4. Check the box to the left of the default accounts created during installation and any other necessary accounts, select Remove.

5. Click Vendor Daemon Configuration and select Administer in the Citrix vendor daemon line. Select Stop, wait 10 seconds. Select Start.

6. Log on to the License Management Console using the specified account.'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x License Server'
  tag check_id: 'C-37408r611920_chk'
  tag severity: 'medium'
  tag gid: 'V-234223'
  tag rid: 'SV-234223r628795_rule'
  tag stig_id: 'CVAD-LS-000135'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-37373r611921_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
