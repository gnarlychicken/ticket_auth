import unittest
from ipaddress import IPv4Address
from ticket_auth.ticket_factory import TicketFactory
from ticket_auth.exception import TicketExpired, TicketDigestError


class TicketFactoryTests(unittest.TestCase):
    def test_ticket_validation(self):
        factory = TicketFactory(b'secret')
        ticket = factory.new('user')

        result = factory.validate(ticket)
        self.assertEqual(result.user_id, 'user')

    def test_ticket_expiration(self):
        factory = TicketFactory(b'secret')
        ticket = factory.new('user', valid_until=500)

        # Should not raise an exception
        factory.validate(ticket, now=499)

        with self.assertRaises(TicketExpired):
            factory.validate(ticket, now=500)

    def test_unusual_user_ids(self):
        factory = TicketFactory(b'secret')
        ticket0 = factory.new('us!er! ')
        ticket1 = factory.new('')

        # Should not raise an exception
        ticket_info1 = factory.validate(ticket1)
        ticket_info0 = factory.validate(ticket0)

        # User should be the same
        self.assertEqual(ticket_info0.user_id, 'us!er! ')
        self.assertEqual(ticket_info1.user_id, '')

    def test_different_digests(self):
        factory0 = TicketFactory(b'secret')
        factory1 = TicketFactory(b'secret2')
        ticket = factory0.new('user')

        # Should not raise an exception
        factory0.validate(ticket)

        with self.assertRaises(TicketDigestError):
            factory1.validate(ticket)

    def test_tokens(self):
        factory0 = TicketFactory(b'secret')
        factory1 = TicketFactory(b'secret')
        tokens = (' ', 'token2,same token', 'token!othertoken')
        ticket = factory0.new('user', tokens=tokens)

        result = factory1.validate(ticket)
        self.assertEqual(result.user_id, 'user')
        self.assertEqual(result.tokens, tokens)

    def test_ip_address(self):
        factory = TicketFactory(b'secret')
        ticket = factory.new('user', client_ip=IPv4Address('127.0.0.1'))

        factory.validate(ticket, client_ip=IPv4Address('127.0.0.1'))
        with self.assertRaises(TicketDigestError):
            factory.validate(ticket)

        with self.assertRaises(TicketDigestError):
            factory.validate(ticket, client_ip=IPv4Address('127.0.0.2'))

        # Test different address types are all handled
        factory.validate(ticket, client_ip='127.0.0.1')
