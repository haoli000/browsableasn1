import binascii
import io
import string

import asn1
import streamlit as st

printable_chars = set(bytes(string.printable, 'ascii'))

tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.ObjectIdentifier: "OBJECT",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.GeneralizedTime: "GENERALIZED TIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET"
}

class_id_to_string_map = {
    asn1.Classes.Universal: "U",
    asn1.Classes.Application: "A",
    asn1.Classes.Context: "C",
    asn1.Classes.Private: "P"
}

object_id_to_string_map = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",

    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",

    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.42": "givenName",

    "1.2.840.113549.1.9.1": "emailAddress",

    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.16": "X509v3 Private Key Usage Period",
    "2.5.29.17": "X509v3 Subject Alternative Name",
    "2.5.29.18": "X509v3 Issuer Alternative Name",
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.30": "X509v3 Name Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies Extension",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.36": "X509v3 Policy Constraints",
    "2.5.29.37": "X509v3 Extended Key Usage"
}


def tag_id_to_string(identifier):
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)


def class_id_to_string(identifier):
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))


def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier


def value_to_string(tag_number, value):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        return object_identifier_to_string(value)
    elif isinstance(value, bytes):
        if all(char in printable_chars for char in value):
            return value.decode('utf-8')
        else:
            return '0x' + str(binascii.hexlify(value).upper())
    elif isinstance(value, str):
        return value
    else:
        return repr(value)


def pretty_print(input_stream, output_stream, indent=""):
    while not input_stream.eof():
        tag = input_stream.peek()
        prefix = '{}{}'.format(class_id_to_string(tag.cls), tag.nr)
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            output_stream.write(indent)
            output_stream.write('{}: {}\n'.format(prefix, value_to_string(tag.nr, value)))
        elif tag.typ == asn1.Types.Constructed:
            output_stream.write(indent)
            output_stream.write('{}:\n'.format(prefix))
            input_stream.enter()
            length = len(prefix) - 1
            pretty_print(input_stream, output_stream, indent + '|' + (' ' * length))
            input_stream.leave()


st.set_page_config(
    page_title="browsable asn1"
)

st.title("browsable asn1")

uploaded_file = st.file_uploader("Choose an ASN.1 BER file")
if uploaded_file is not None:
    bytes_data = uploaded_file.getvalue()
    decoder = asn1.Decoder()
    decoder.start(bytes_data)
    out = io.StringIO()
    pretty_print(decoder, out)
    st.code(out.getvalue())

st.caption('This is just a simple tool to decode ASN.1 BER files without support of any schemas.')
st.caption('To decode 3GPP CDRs according to TS 32.297 and 32.298, check [browsable cdr](https://browsablecdr.vercel.app/).')
