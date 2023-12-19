control 'SV-223630' do
  title 'IBM z/OS UNIX HFS MapName files security parameters must be properly specified.'
  desc 'Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Refer to the logical parmlib data sets, example: SYS1.PARMLIB(BPXPRMxx), for the following FILESYSTYPE entry:

FILESYSTYPE TYPE(AUTOMNT) ENTRYPOINT(BPXTAMD)

If the above entry is not found or is commented out in the BPXPRMxx member(s), this is Not Applicable.

From the ISPF Command Shell enter:
OMVS
cd /etc
cat auto.master

Perform a contents list for the file identified.
Example:
cat u.map
Note: The /etc/auto.master HFS file (and the use of Automount) is optional. If the file does not exist, this is Not Applicable.

Note: The setuid parameter and the security parameter have a significant security impact. For this reason these parameters must be explicitly specified and not allowed to default.

If each MapName file specifies the “setuid No” and “security Yes” statements for each automounted directory, this is not a finding.

If there is any deviation from the required values, this is a finding.'
  desc 'fix', 'Review the settings in /etc/auto.master and /etc/mapname for z/OS UNIX security parameters and configure the values to conform to the specifications below.

The /etc/auto.master HFS file (and the use of Automount) is optional. 

The setuid parameter and the security parameter have a significant security impact. For this reason these parameters must be explicitly specified and not be allowed to default.

Each MapName file will specify the “setuid NO” and “security YES" statements for each automounted directory.

If there is a deviation from the required values, documentation must exist for the deviation.

Security NO disables security checking for file access. Security NO is only allowed on test and development domains.

Setuid YES allows a user to run under a different UID/GID identity. Justification documentation is required to validate the use of setuid YES.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25303r504848_chk'
  tag severity: 'medium'
  tag gid: 'V-223630'
  tag rid: 'SV-223630r533198_rule'
  tag stig_id: 'ACF2-US-000150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25291r504849_fix'
  tag 'documentable'
  tag legacy: ['SV-107069', 'V-97965']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
