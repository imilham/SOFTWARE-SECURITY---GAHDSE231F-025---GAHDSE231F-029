import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:crypto/crypto.dart';
import 'dart:convert';

class ChatScreen extends StatefulWidget {
  @override
  _ChatScreenState createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _controller = TextEditingController();
  final FirebaseAuth _auth = FirebaseAuth.instance;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  // Ensure the key is exactly 32 bytes for AES-256
  final key = encrypt.Key.fromUtf8('your-32-char-long-key-for-aes256'); // Use exactly 32 chars for AES-256
  final iv = encrypt.IV.fromLength(16); // AES Initialization Vector should be 16 bytes

  String _userId = '';

  @override
  void initState() {
    super.initState();
    _auth.currentUser?.reload();
    _userId = _auth.currentUser?.uid ?? '';
  }

  String _encryptMessage(String message) {
    try {
      final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
      final encrypted = encrypter.encrypt(message, iv: iv);
      return encrypted.base64;
    } catch (e) {
      print("Encryption error: $e");
      return '';
    }
  }

  String _decryptMessage(String encryptedMessage) {
    try {
      final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
      final decrypted = encrypter.decrypt64(encryptedMessage, iv: iv);
      return decrypted;
    } catch (e) {
      print("Decryption error: $e");
      return '';
    }
  }

  String _generateHash(String message) {
    return sha256.convert(utf8.encode(message)).toString();
  }

  bool _verifyHash(String message, String receivedHash) {
    return _generateHash(message) == receivedHash;
  }

  void _sendMessage() async {
    final message = _sanitizeInput(_controller.text);
    if (_isValidInput(message)) {
      final encryptedMessage = _encryptMessage(message);
      final messageHash = _generateHash(message);

      try {
        await _firestore.collection('messages').add({
          'senderId': _userId,
          'message': encryptedMessage,
          'hash': messageHash,
          'timestamp': FieldValue.serverTimestamp(),
        });
        _controller.clear();
      } catch (e) {
        print("Failed to send message: $e");
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to send message: $e')),
        );
      }
    }
  }

  String _sanitizeInput(String input) {
    final RegExp exp = RegExp(r"<[^>]*>", multiLine: true, caseSensitive: true);
    return input.replaceAll(exp, '');
  }

  bool _isValidInput(String input) {
    return input.isNotEmpty;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text("Secure P2P Chat")),
      body: Column(
        children: [
          Expanded(
            child: StreamBuilder<QuerySnapshot>(
              stream: _firestore.collection('messages').orderBy('timestamp', descending: true).snapshots(),
              builder: (context, snapshot) {
                if (!snapshot.hasData) return Center(child: CircularProgressIndicator());

                final messages = snapshot.data!.docs;
                List<Widget> messageWidgets = [];

                for (var message in messages) {
                  final messageData = message.data() as Map<String, dynamic>;
                  final senderId = messageData['senderId'];
                  final encryptedMessage = messageData['message'];
                  final messageHash = messageData['hash'];

                  final decryptedMessage = _decryptMessage(encryptedMessage);

                  if (_verifyHash(decryptedMessage, messageHash)) {
                    final messageWidget = ListTile(
                      title: Text(decryptedMessage),
                      subtitle: Text(senderId == _userId ? "You" : "Other",style: const TextStyle(color:  Colors.red )),
                    );
                    messageWidgets.add(messageWidget);
                  } else {
                    final messageWidget = ListTile(
                      title: Text("Message Integrity Compromised!"),
                      subtitle: Text(senderId == _userId ? "You" : "Other"),
                    );
                    messageWidgets.add(messageWidget);
                  }
                }

                return ListView(
                  reverse: true,
                  children: messageWidgets,
                );
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _controller,
                    decoration: InputDecoration(hintText: "Enter your message..."),
                  ),
                ),
                IconButton(
                  icon: Icon(Icons.send),
                  onPressed: _sendMessage,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}