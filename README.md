## MikroTik: Скрипт Fail2ban

Скрипт запускается каждую минуту и добавляет в BLACKLIST на 1 час те IP, с которых больше 10 неудачных логинов (WinBox/SSH/Web) за последний час.

```powershell
# MIKROTIK TEMPLATE
# The script runs every minute and adds to the BLACKLIST for 1 hour those IPs from which there have been more than 10 unsuccessful logins (WinBox/SSH/Web) in the last hour

# Remove static records from the BLACKLIST address list
/ip firewall address-list remove [find dynamic=no list=BLACKLIST]

# Add Fail2ban firewall rule
/ip firewall filter add action=drop chain=input comment="DROP INPUT WINBOX/SSH/WEB TO SELF FROM BLACKLIST" dst-address-type=local dst-port=8291,32223,80,443 protocol=tcp src-address-list=BLACKLIST

# Add Fail2ban script
/system script remove [find name=fail2ban]
/system script add name=fail2ban source="{:local a [:toarray \"\"];:local cd;:local ds [/system clock get date];:if ([:find \$ds \"-\"]) do={:set cd [:pick \$ds 5 10]};:if ([:find \$ds \"/\"]) do={:set cd [:pick \$ds 0 6]};:local ct [/system clock get time];:local l [/log find where topics=system,error,critical message~\"login failure for user \" message~\" from \" message~\" via \"];:foreach le in=\$l do={:local ed \$cd;:local et [/log get \$le time];:if ([:len \$et]=14) do={:set ed [:pick \$et 0 5];:set et [:pick \$et 6 14]};:if ([:len \$et]=15) do={:set ed [:pick \$et 0 6];:set et [:pick \$et 7 15]};:if (\$ed=\$cd) do={:local td (\$ct-\$et);:if (\$td~\"-\") do={:set td (\$td+1d)};:if (\$td<=1h) do={:local em [/log get \$le message];:local fp [:find \$em \" from \"];:if (\$fp) do={:local ips (\$fp+6);:local ipe [:find \$em \" \" \$ips];:local ip [:pick \$em \$ips \$ipe];:set (\$a->\"\$ip\") ((\$a->\"\$ip\")+1)}}}};:foreach ip,c in=\$a do={:local ipw [/ip firewall address-list find list=TRUSTED-WANS address=\$ip];:local ipb [/ip firewall address-list find list=BLACKLIST address=\$ip];:if ([:len \$ipw]=0 && [:len \$ipb]=0) do={:if (\$c>10) do={:log warning (\"BLACKLISTED: \$ip - \$c failed logins in the last hour\");/ip firewall address-list add list=BLACKLIST address=\$ip timeout=1h}}}}"

# Add Fail2ban scheduler
/system scheduler remove [find name=fail2ban]
/system scheduler add name=fail2ban interval=1m on-event=fail2ban
```

### Fail2ban script Source code

```powershell
{
  :local arrIPCount [:toarray ""]
  :local currentDate
  :local dateStr [/system clock get date]
  :if ([:find $dateStr "-"]) do={:set currentDate [:pick $dateStr 5 10]}
  :if ([:find $dateStr "/"]) do={:set currentDate [:pick $dateStr 0 6]}
  :local currentTime [/system clock get time]
  :local allLogs [/log find where topics=system,error,critical message~"login failure for user " message~" from " message~" via "]
  :foreach logEntry in=$allLogs do={
    :local entryDate $currentDate
    :local entryTime [/log get $logEntry time]
    :if ([:len $entryTime]=14) do={
     :set entryDate [:pick $entryTime 0 5]
     :set entryTime [:pick $entryTime 6 14]
    }
    :if ([:len $entryTime]=15) do={
     :set entryDate [:pick $entryTime 0 6]
     :set entryTime [:pick $entryTime 7 15]
    }
    :if ($entryDate=$currentDate) do={
      :local timeDiff ($currentTime-$entryTime)
      :if ($timeDiff~"-") do={:set timeDiff ($timeDiff+1d)}
      :if ($timeDiff<=1h) do={
        :local entryMessage [/log get $logEntry message]
        :local fromPos [:find $entryMessage " from "]
        :if ($fromPos) do={
          :local ipStart ($fromPos+6)
          :local ipEnd [:find $entryMessage " " $ipStart]
          :local ip [:pick $entryMessage $ipStart $ipEnd]
          :set ($arrIPCount->"$ip") (($arrIPCount->"$ip")+1)
        }
      }
    }
  }
  :foreach ip,count in=$arrIPCount do={
    :local ipIsWhitelisted [/ip firewall address-list find list=TRUSTED-WANS address=$ip]
    :local ipIsBlacklisted [/ip firewall address-list find list=BLACKLIST    address=$ip]
    :if ([:len $ipIsWhitelisted]=0 && [:len $ipIsBlacklisted]=0) do={
      :if ($count>10) do={
        :log warning ("BLACKLISTED: $ip - $count failed logins in the last hour")
        /ip firewall address-list add list=BLACKLIST address=$ip timeout=1h
      }
    }
  }
}
```
