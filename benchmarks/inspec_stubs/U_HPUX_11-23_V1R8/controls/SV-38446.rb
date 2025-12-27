control 'SV-38446' do
  title 'The delay between login prompts following a failed login attempt must be at least 4 seconds.'
  desc 'Enforcing a delay between consecutive failed login attempts increases protection against automated password guessing attacks.'
  desc 'check', 'For Trusted Mode:
Check the t_logdelay setting.
# more /tcb/files/auth/system/default

Verify the value of the t_logdelay variable. If the value is less than 4, this is a finding.

For SMSE:
By default, PAM executes a built-in, 3 second standard delay if user authentication fails. This delay cannot be extended. The “nodelay” parameter disables the built-in delay. Ensure that the “nodelay” parameter is not found in the /etc/pam.conf file.

The HP-SMSE environment does not meet the failed authentication 4 second minimum delay requirement. This check will always result in a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface to ensure that the t_logdelay setting is 4.

For SMSE:
There is no fix, however, there are attack mitigations to minimize risk (see mitigations).'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36250r2_chk'
  tag severity: 'medium'
  tag gid: 'V-768'
  tag rid: 'SV-38446r3_rule'
  tag stig_id: 'GEN000480'
  tag gtitle: 'GEN000480'
  tag fix_id: 'F-31507r2_fix'
  tag 'documentable'
  tag mitigations: 'GEN000480'
  tag mitigation_control: [
    {"#text": "Attack mitigations to minimize risk:\n\n1. Ensure that the “nodelay” parameter is not found in the /etc/pam.conf file.\n2. In the file /opt/ssh/etc/sshd_config, the “MaxAuthTries” attribute must be explicitly set to “1”. This attribute controls the maximum number of authentication attempts permitted per SSH daemon connection.\n3. In the file /opt/ssh/etc/sshd_config, the “MaxStartups” attribute must be explicitly set to an organization defined value of “10” (the default) or less. This attribute controls the maximum number of unauthenticated connections to the SSH daemon. \n4. IPFilter DCA mode is disabled by default, and must be explicitly enabled. Set the following attribute in the /etc/rc.config.d/ipfconf file:\nDCA_START=1 \n\nThe below /etc/opt/ipf/ipf.conf file rule specifies a connection limit of “",
      "limit" => [{    "#text": "“ for all hosts when attempting to connect to port “",
          "sshd" => [    {        "#text": "“. The “",
              "sshd" => [        {            "#text": "“ and “",
                  "limit" => [            {                "#text": "“ must be set to organization defined values. Per  vendor documentation, this rule must be the next-to-last rule in /etc/opt/ipf/ipf.conf. The final rule in the file must define the default connection limit. See the below example for the last 2 line entries in /etc/opt/ipf/ipf.conf (note that the double quotes are for emphasis only):\n“pass in proto tcp from any to any port =",
                      "sshd" => [                {                    "#text": "keep limit",
                          "limit": "“\n“block in from any to any”\n\nSave the file before exiting the editor. The system should not require restarting for the new rule(s) to take effect.",
                          "Responsibility": "System Administrator",
                          "IAControls": "ECLO-1, ECLO-2"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }]}
  ]
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
