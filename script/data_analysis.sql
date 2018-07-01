/* Dados API */
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=4 and time < 605 group by service, session_id) group by service;
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=4 and time < 125 group by service, session_id) group by service;
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=125 and time < 245 group by service, session_id) group by service;
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=245 and time < 365 group by service, session_id) group by service;
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=365 and time < 485 group by service, session_id) group by service;
select service, group_concat(total) from (select service, count(id) as total from apidata where time >=485 and time < 605 group by service, session_id) group by service;

/* Dados Trafego */
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=4 and time < 605 group by session_id) group by session_id;
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=4 and time < 125 group by session_id) group by session_id;
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=125 and time < 245 group by session_id) group by session_id;
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=245 and time < 365 group by session_id) group by session_id;
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=365 and time < 485 group by session_id) group by session_id;
select etc, glance, keystone, neutron, nova, total from (select session_id, sum(m_total) as total, sum(m_etc) as etc, sum(m_glance) as glance, sum(m_neutron) as neutron, sum(m_keystone) as keystone, sum(m_nova) as nova from meteringdata where time >=485 and time < 605 group by session_id) group by session_id;
