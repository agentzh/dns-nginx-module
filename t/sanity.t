# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 2 * blocks();

no_shuffle();
no_long_string();

run_tests();

__DATA__

=== TEST 1:
--- config
    location /main {
        dns_pass 10.0.1.1;
        #dns_pass localhost:51432;
        dns_total_timeout 2s;
    }
--- request
GET /main
--- response_body
name was resolved to 74.125.224.48
name was resolved to 74.125.224.52
name was resolved to 74.125.224.50
name was resolved to 74.125.224.49
name was resolved to 74.125.224.51
--- timeout: 5

