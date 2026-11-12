# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestRpkiSocket(frrtest.TestMultiOut):
    program = "./test_rpki_socket"


TestRpkiSocket.okfail("IPv4 TCP")
TestRpkiSocket.okfail("IPv6 TCP")
TestRpkiSocket.okfail("hostname and service")
TestRpkiSocket.okfail("named VRF")
TestRpkiSocket.okfail("null cache")
TestRpkiSocket.okfail("thread registration fails")
TestRpkiSocket.okfail("missing default VRF")
TestRpkiSocket.okfail("missing named VRF")
TestRpkiSocket.okfail("inactive VRF")
TestRpkiSocket.okfail("unknown VRF ID")
TestRpkiSocket.okfail("resolver failure")
TestRpkiSocket.okfail("socket creation failure")
TestRpkiSocket.okfail("connection failure closes socket")
TestRpkiSocket.okfail("SSH type without SSH support")
TestRpkiSocket.okfail("port zero is passed to resolver")
TestRpkiSocket.okfail("minimum nonzero port")
TestRpkiSocket.okfail("maximum port")
TestRpkiSocket.okfail("file descriptor zero is success")
TestRpkiSocket.okfail("negative cache type")
TestRpkiSocket.okfail("maximum signed cache type")
TestRpkiSocket.okfail("minimum signed cache type")
TestRpkiSocket.okfail("full IPv6 address")
TestRpkiSocket.okfail("IPv4 mapped IPv6")
TestRpkiSocket.okfail("thread already registered")
