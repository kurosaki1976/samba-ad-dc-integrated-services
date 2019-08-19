<?php
$config = array();
// Database
$config['db_dsnw'] = 'DBDRIVER://DBUSER:DBUSERPASSWD@DBHOST/DBNAME';
// IMAP
$config['default_host'] = 'ssl://127.0.0.1';
$config['default_port'] = 993;
$config['imap_auth_type'] = 'LOGIN';
$config['imap_delimiter'] = '/';
$config['imap_conn_options'] = array(
    'ssl' => array(
        'verify_peer'       => true,
        'verify_peer_name'  => false,
        'cafile'            => '/etc/ssl/certs/exampleMail.crt',
        'allow_self_signed' => false,
        'ciphers'           => 'TLSv1+HIGH:!aNull:@STRENGTH',
        'peer_name'         => 'mail.example.tld',
    ),
);
$config['imap_vendor'] = 'dovecot';
// SMTP (submission)
$config['smtp_server'] = 'tls://127.0.0.1';
$config['smtp_port'] = 587;
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['smtp_auth_type'] = 'LOGIN';
$config['smtp_conn_options'] = array(
    'ssl' => array(
        'verify_peer'       => true,
        'verify_peer_name'  => false,
        'cafile'            => '/etc/ssl/certs/exampleMail.crt',
        'allow_self_signed' => false,
        'ciphers'           => 'TLSv1+HIGH:!aNull:@STRENGTH',
        'peer_name'         => 'mail.example.tld',
    ),
);
// System & User preferences
$config['mail_domain'] = 'example.tld';
$config['username_domain'] = 'example.tld';
$config['support_url'] = 'https://www.example.tld';
$config['product_name'] = 'Roundcube Webmail';
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
$config['plugins'] = array(
    'archive',
    'zipdownload',
    'newmail_notifier',
);
$config['skin'] = 'larry';
$config['cipher_method'] = 'AES-256-CBC';
$config['force_https'] = true;
$config['useragent'] = 'Roundcube Webmail';
$config['quota_zero_as_unlimited'] = true;
$config['message_show_email'] = true;
$config['language'] = 'es_ES';
$config['create_default_folders'] = true;
$config['timezone'] = 'America/Havana';
$config['date_format'] = 'd/m/Y';
$config['time_format'] = 'g:i a';
$config['identities_level'] = 3;
$config['login_autocomplete'] = 0;
$config['refresh_interval'] = 600;
$config['message_sort_col'] = 'date';
$config['message_sort_order'] = 'DESC';
$config['list_cols'] = array(
    'flag',
    'attachment',
    'fromto',
    'subject',
    'status',
    'date',
    'size',
);
$config['addressbook_sort_col'] = 'firstname';
$config['show_images'] = 1;
$config['default_font_size'] = '12pt';
$config['layout'] = 'desktop';
$config['mdn_use_from'] = true;
$config['autocomplete_addressbooks'] = array(
    'sql',
    'global_ldap_abook'
);
// Samba AD DC Address Book
$config['ldap_public']["global_ldap_abook"] = array(
    'name'              => 'Directorio',
    'hosts'             => array('dc.example.tld'),
    'port'              => 389,
    'use_tls'           => false,
    'ldap_version'      => '3',
    'network_timeout'   => 10,
    'user_specific'     => false,
    'base_dn'           => 'OU=ACME,DC=example,DC=tld',
    'bind_dn'           => 'postfix@example.tld',
    'bind_pass'         => 'P@s$w0rd.345',
    'writable'          => false,
    'search_fields'     => array(
        'mail',
        'cn',
        'sAMAccountName',
        'displayName',
        'sn',
        'givenName',
    ),
    'fieldmap' => array(
        'name'          => 'cn',
        'surname'       => 'sn',
        'firstname'     => 'givenName',
        'title'         => 'title',
        'email'         => 'mail:*',
        'phone:work'    => 'telephoneNumber',
        'phone:mobile'  => 'mobile',
        'phone:workfax' => 'facsimileTelephoneNumber',
        'street'        => 'street',
        'zipcode'       => 'postalCode',
        'locality'      => 'l',
        'department'    => 'department',
        'notes'         => 'description',
        'photo'         => 'jpegPhoto',
    ),
    'sort'          => 'cn',
    'scope'         => 'sub',
    'filter'        => '(&(|(objectclass=person))(!(mail=archive@example.tld))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    'fuzzy_search'  => true,
    'vlv'           => false,
    'sizelimit'     => '0',
    'timelimit'     => '0',
    'referrals'     => false,
    'group_filters' => array(
        'departments' => array(
            'name'    => 'Listas',
            'scope'   => 'sub',
            'base_dn' => 'OU=Email,OU=ACME,DC=example,DC=tld',
            'filter'  => '(objectClass=group)',
        ),
    ),
);
