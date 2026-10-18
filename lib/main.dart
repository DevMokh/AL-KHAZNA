import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart'
    show Argon2id, Xchacha20, AesGcm, Cipher, SecretKey, SecretBox, Mac, SecretBoxAuthenticationError;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const VaultApp());

class Level {
  const Level(this.name, this.mem, this.iter);
  final String name;
  final int mem, iter;
}

const levels = [
  Level('عادي', 19456, 2),
  Level('قوي', 65536, 3),
  Level('أقصى', 131072, 3),
];

final ValueNotifier<int> wipe = ValueNotifier<int>(0);

Cipher _cipher(int id) => id == 1 ? Xchacha20.poly1305Aead() : AesGcm.with256bits();

Uint8List _rand(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
}

Uint8List _u32(int v) => (ByteData(4)..setUint32(0, v)).buffer.asUint8List();

Future<List<int>> _derive(Map<String, Object> a) async {
  final kdf = Argon2id(
    memory: a['mem'] as int,
    parallelism: 1,
    iterations: a['iter'] as int,
    hashLength: 32,
  );
  final key = await kdf.deriveKeyFromPassword(
    password: a['pw'] as String,
    nonce: a['salt'] as List<int>,
  );
  return key.extractBytes();
}

Future<String> encryptText(String text, String pw, int algoId, Level lvl) async {
  final salt = _rand(16);
  final nonce = _rand(algoId == 1 ? 24 : 12);
  final hb = BytesBuilder()
    ..add([0x4B, 0x43, 1, algoId])
    ..add(_u32(lvl.mem))
    ..addByte(lvl.iter)
    ..addByte(1)
    ..add(salt)
    ..add(nonce);
  final header = hb.toBytes();
  final keyBytes = await compute(_derive, <String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': lvl.mem,
    'iter': lvl.iter,
  });
  final box = await _cipher(algoId).encrypt(
    utf8.encode(text),
    secretKey: SecretKey(keyBytes),
    nonce: nonce,
    aad: header,
  );
  final out = BytesBuilder()
    ..add(header)
    ..add(box.cipherText)
    ..add(box.mac.bytes);
  return 'KC1.${base64Url.encode(out.toBytes())}';
}

Future<String> decryptText(String input, String pw) async {
  final s = input.replaceAll(RegExp(r'\s'), '');
  if (!s.startsWith('KC1.')) throw const FormatException('format');
  final b = base64Url.decode(base64Url.normalize(s.substring(4)));
  if (b.length < 26 + 12 + 16 || b[0] != 0x4B || b[1] != 0x43 || b[2] != 1) {
    throw const FormatException('format');
  }
  final algoId = b[3];
  if (algoId != 1 && algoId != 2) throw const FormatException('algo');
  final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
  final iter = b[8];
  if (mem < 8192 || mem > 262144 || iter < 1 || iter > 10 || b[9] != 1) {
    throw const FormatException('params');
  }
  final hLen = 26 + (algoId == 1 ? 24 : 12);
  if (b.length < hLen + 16) throw const FormatException('format');
  final header = b.sublist(0, hLen);
  final salt = b.sublist(10, 26);
  final nonce = b.sublist(26, hLen);
  final ct = b.sublist(hLen, b.length - 16);
  final mac = b.sublist(b.length - 16);
  final keyBytes = await compute(_derive, <String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': mem,
    'iter': iter,
  });
  final clear = await _cipher(algoId).decrypt(
    SecretBox(ct, nonce: nonce, mac: Mac(mac)),
    secretKey: SecretKey(keyBytes),
    aad: header,
  );
  return utf8.decode(clear);
}

double entropyBits(String p) {
  var pool = 0;
  if (p.contains(RegExp(r'[a-z]'))) pool += 26;
  if (p.contains(RegExp(r'[A-Z]'))) pool += 26;
  if (p.contains(RegExp(r'[0-9]'))) pool += 10;
  if (p.contains(RegExp(r'[^a-zA-Z0-9]'))) pool += 33;
  return pool == 0 ? 0 : p.length * (log(pool) / ln2);
}

String genPassword([int n = 20]) {
  const a = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#\$%^&*-_=+?';
  final r = Random.secure();
  return List<String>.generate(n, (_) => a[r.nextInt(a.length)]).join();
}

Future<void> copySecure(BuildContext c, String text) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (c.mounted) {
    ScaffoldMessenger.of(c).showSnackBar(const SnackBar(
        content: Text('اتنسخ، وهيتمسح من الحافظة بعد 30 ثانية')));
  }
  Timer(const Duration(seconds: 30), () async {
    final d = await Clipboard.getData(Clipboard.kTextPlain);
    if (d?.text == text) await Clipboard.setData(const ClipboardData(text: ''));
  });
}

class VaultApp extends StatelessWidget {
  const VaultApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'الخزنة',
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF00C853), brightness: Brightness.dark),
      ),
      builder: (c, child) =>
          Directionality(textDirection: TextDirection.rtl, child: child!),
      home: const VaultHome(),
    );
  }
}

class VaultHome extends StatefulWidget {
  const VaultHome({super.key});
  @override
  State<VaultHome> createState() => _VaultHomeState();
}

class _VaultHomeState extends State<VaultHome> with WidgetsBindingObserver {
  bool secure = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _loadSecure();
  }

  Future<void> _loadSecure() async {
    final p = await SharedPreferences.getInstance();
    final v = p.getBool('secure') ?? true;
    if (mounted) setState(() => secure = v);
    SecureWindow.set(v);
  }

  Future<void> _toggleSecure() async {
    final p = await SharedPreferences.getInstance();
    setState(() => secure = !secure);
    await p.setBool('secure', secure);
    SecureWindow.set(secure);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) wipe.value++;
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('الخزنة'),
          actions: [
            IconButton(
              icon: Icon(secure ? Icons.shield : Icons.shield_outlined),
              tooltip: secure ? 'منع لقطات الشاشة: شغّال' : 'منع لقطات الشاشة: موقوف',
              onPressed: _toggleSecure,
            ),
          ],
          bottom: const TabBar(tabs: [
            Tab(icon: Icon(Icons.lock), text: 'تشفير'),
            Tab(icon: Icon(Icons.lock_open), text: 'فك التشفير'),
            Tab(icon: Icon(Icons.inventory_2), text: 'خزنتي'),
          ]),
        ),
        body: const TabBarView(children: [EncryptTab(), DecryptTab(), VaultTab()]),
      ),
    );
  }
}

class PwField extends StatefulWidget {
  const PwField(this.ctl,
      {super.key, this.generate = false, this.onChanged, this.label = 'كلمة السر'});
  final TextEditingController ctl;
  final String label;
  final bool generate;
  final VoidCallback? onChanged;
  @override
  State<PwField> createState() => _PwFieldState();
}

class _PwFieldState extends State<PwField> {
  bool show = false;
  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: widget.ctl,
      obscureText: !show,
      autocorrect: false,
      enableSuggestions: false,
      enableIMEPersonalizedLearning: false,
      keyboardType: TextInputType.visiblePassword,
      onChanged: (_) => widget.onChanged?.call(),
      decoration: InputDecoration(
        labelText: widget.label,
        border: const OutlineInputBorder(),
        suffixIcon: Row(mainAxisSize: MainAxisSize.min, children: [
          if (widget.generate)
            IconButton(
              icon: const Icon(Icons.casino),
              tooltip: 'توليد كلمة سر قوية',
              onPressed: () {
                widget.ctl.text = genPassword();
                setState(() => show = true);
                widget.onChanged?.call();
              },
            ),
          IconButton(
            icon: Icon(show ? Icons.visibility_off : Icons.visibility),
            onPressed: () => setState(() => show = !show),
          ),
        ]),
      ),
    );
  }
}

class OutBox extends StatelessWidget {
  const OutBox(this.text, {super.key});
  final String text;
  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SelectableText(text, style: const TextStyle(fontSize: 15)),
          Align(
            alignment: AlignmentDirectional.centerEnd,
            child: TextButton.icon(
              onPressed: () => copySecure(context, text),
              icon: const Icon(Icons.copy),
              label: const Text('نسخ'),
            ),
          ),
        ]),
      ),
    );
  }
}

class EncryptTab extends StatefulWidget {
  const EncryptTab({super.key});
  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab>
    with AutomaticKeepAliveClientMixin<EncryptTab> {
  final text = TextEditingController();
  final pw = TextEditingController();
  int algo = 1, lvl = 1;
  String? out, err;
  bool busy = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_clear);
  }

  @override
  void dispose() {
    wipe.removeListener(_clear);
    text.dispose();
    pw.dispose();
    super.dispose();
  }

  void _clear() {
    text.clear();
    pw.clear();
    if (mounted) setState(() => out = null);
  }

  Future<void> _go() async {
    if (text.text.isEmpty) {
      setState(() => err = 'اكتب النص الأول');
      return;
    }
    if (pw.text.length < 8) {
      setState(() => err = 'كلمة السر لازم تكون 8 حروف على الأقل');
      return;
    }
    setState(() {
      busy = true;
      err = null;
      out = null;
    });
    try {
      final r = await encryptText(text.text, pw.text, algo, levels[lvl]);
      if (mounted) setState(() => out = r);
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء التشفير');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final bits = entropyBits(pw.text);
    final label = bits < 40
        ? 'ضعيفة'
        : bits < 60
            ? 'متوسطة'
            : bits < 80
                ? 'قوية'
                : 'ممتازة';
    return ListView(padding: const EdgeInsets.all(16), children: [
      TextField(
        controller: text,
        maxLines: 6,
        decoration: const InputDecoration(
            labelText: 'النص المراد تشفيره', border: OutlineInputBorder()),
      ),
      const SizedBox(height: 12),
      PwField(pw, generate: true, onChanged: () => setState(() {})),
      const SizedBox(height: 6),
      LinearProgressIndicator(value: (bits / 100).clamp(0.0, 1.0)),
      Text('قوة كلمة السر: $label (${bits.round()} بت)'),
      const SizedBox(height: 12),
      const Text('الخوارزمية'),
      SegmentedButton<int>(
        segments: const [
          ButtonSegment(value: 1, label: Text('XChaCha20')),
          ButtonSegment(value: 2, label: Text('AES-256-GCM')),
        ],
        selected: {algo},
        onSelectionChanged: (v) => setState(() => algo = v.first),
      ),
      const SizedBox(height: 8),
      const Text('مستوى الحماية (أعلى = أبطأ وأصعب على المخترق)'),
      SegmentedButton<int>(
        segments: [
          for (var i = 0; i < levels.length; i++)
            ButtonSegment(value: i, label: Text(levels[i].name)),
        ],
        selected: {lvl},
        onSelectionChanged: (v) => setState(() => lvl = v.first),
      ),
      const SizedBox(height: 16),
      FilledButton.icon(
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock),
        label: Text(busy ? 'جارٍ التشفير...' : 'تشفير'),
      ),
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (out != null) OutBox(out!),
      const SizedBox(height: 16),
      const Text(
        'Argon2id لاشتقاق المفتاح + تشفير مُصادَق (AEAD). مفتاح ونونس جديدين لكل رسالة، '
        'وأي تعديل في النص المشفّر أو إعداداته بيفشّل فك التشفير.',
        style: TextStyle(fontSize: 12, color: Colors.grey),
      ),
    ]);
  }
}

class DecryptTab extends StatefulWidget {
  const DecryptTab({super.key});
  @override
  State<DecryptTab> createState() => _DecryptTabState();
}

class _DecryptTabState extends State<DecryptTab>
    with AutomaticKeepAliveClientMixin<DecryptTab> {
  final input = TextEditingController();
  final pw = TextEditingController();
  String? out, err;
  bool busy = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_clear);
  }

  @override
  void dispose() {
    wipe.removeListener(_clear);
    input.dispose();
    pw.dispose();
    super.dispose();
  }

  void _clear() {
    input.clear();
    pw.clear();
    if (mounted) setState(() => out = null);
  }

  Future<void> _go() async {
    if (input.text.trim().isEmpty || pw.text.isEmpty) {
      setState(() => err = 'ادخل النص المشفّر وكلمة السر');
      return;
    }
    setState(() {
      busy = true;
      err = null;
      out = null;
    });
    try {
      final r = await decryptText(input.text, pw.text);
      if (mounted) setState(() => out = r);
    } on FormatException {
      if (mounted) setState(() => err = 'الصيغة مش صحيحة أو النص ناقص');
    } on SecretBoxAuthenticationError {
      if (mounted) setState(() => err = 'كلمة السر غلط أو النص اتعدّل');
    } catch (_) {
      if (mounted) setState(() => err = 'كلمة السر غلط أو النص اتعدّل');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return ListView(padding: const EdgeInsets.all(16), children: [
      TextField(
        controller: input,
        maxLines: 6,
        decoration: InputDecoration(
          labelText: 'النص المشفّر (يبدأ بـ KC1.)',
          border: const OutlineInputBorder(),
          suffixIcon: IconButton(
            icon: const Icon(Icons.paste),
            tooltip: 'لصق',
            onPressed: () async {
              final d = await Clipboard.getData(Clipboard.kTextPlain);
              if (d?.text != null) setState(() => input.text = d!.text!);
            },
          ),
        ),
      ),
      const SizedBox(height: 12),
      PwField(pw),
      const SizedBox(height: 16),
      FilledButton.icon(
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock_open),
        label: Text(busy ? 'جارٍ فك التشفير...' : 'فك التشفير'),
      ),
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (out != null) OutBox(out!),
    ]);
  }
}


class SecureWindow {
  static const _ch = MethodChannel('vault/secure');
  static Future<void> set(bool on) async {
    try {
      await _ch.invokeMethod('setSecure', {'on': on});
    } catch (_) {}
  }
}

class Session {
  Session(this.slot, this.key, this.header, this.items);
  final String slot;
  final Uint8List key, header;
  List<Map<String, dynamic>> items;
}

class VaultStore {
  static Future<Uint8List> _key(String pw, List<int> salt, int mem, int iter) async =>
      Uint8List.fromList(await compute(_derive, <String, Object>{
        'pw': pw,
        'salt': salt,
        'mem': mem,
        'iter': iter,
      }));

  static Future<void> save(Session s) async {
    final nonce = _rand(24);
    final box = await _cipher(1).encrypt(
      utf8.encode(jsonEncode(s.items)),
      secretKey: SecretKey(s.key),
      nonce: nonce,
      aad: s.header,
    );
    final out = BytesBuilder()
      ..add(s.header)
      ..add(nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);
    final p = await SharedPreferences.getInstance();
    await p.setString(s.slot, base64Url.encode(out.toBytes()));
  }

  static Future<Session> create(
      String slot, String pw, List<Map<String, dynamic>> items) async {
    final lvl = levels[1];
    final salt = _rand(16);
    final header = (BytesBuilder()
          ..add([0x4B, 0x56, 1, 1])
          ..add(_u32(lvl.mem))
          ..addByte(lvl.iter)
          ..addByte(1)
          ..add(salt))
        .toBytes();
    final s = Session(slot, await _key(pw, salt, lvl.mem, lvl.iter), header, items);
    await save(s);
    return s;
  }

  static Future<Session?> tryOpen(String slot, String pw) async {
    try {
      final p = await SharedPreferences.getInstance();
      final blob = p.getString(slot);
      if (blob == null) return null;
      final b = base64Url.decode(base64Url.normalize(blob));
      if (b.length < 26 + 24 + 16 || b[0] != 0x4B || b[1] != 0x56 || b[2] != 1) {
        return null;
      }
      final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
      final iter = b[8];
      if (mem < 8192 || mem > 262144 || iter < 1 || iter > 10 || b[9] != 1) return null;
      final header = b.sublist(0, 26);
      final key = await _key(pw, b.sublist(10, 26), mem, iter);
      final clear = await _cipher(1).decrypt(
        SecretBox(b.sublist(50, b.length - 16),
            nonce: b.sublist(26, 50), mac: Mac(b.sublist(b.length - 16))),
        secretKey: SecretKey(key),
        aad: header,
      );
      final list = (jsonDecode(utf8.decode(clear)) as List)
          .map((e) => Map<String, dynamic>.from(e as Map))
          .toList();
      return Session(slot, key, header, list);
    } catch (_) {
      return null;
    }
  }
}

class SecretRow extends StatefulWidget {
  const SecretRow(this.label, this.value, this.hide, {super.key});
  final String label, value;
  final bool hide;
  @override
  State<SecretRow> createState() => _SecretRowState();
}

class _SecretRowState extends State<SecretRow> {
  bool show = false;
  @override
  Widget build(BuildContext context) {
    if (widget.value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(widget.label, style: const TextStyle(fontSize: 12, color: Colors.grey)),
            Text(widget.hide && !show ? '••••••••' : widget.value),
          ]),
        ),
        if (widget.hide)
          IconButton(
            icon: Icon(show ? Icons.visibility_off : Icons.visibility),
            onPressed: () => setState(() => show = !show),
          ),
        IconButton(
          icon: const Icon(Icons.copy),
          onPressed: () => copySecure(context, widget.value),
        ),
      ]),
    );
  }
}

const _sampleItems = <Map<String, dynamic>>[
  {'id': 'd1', 't': 'قائمة المشتريات', 'u': '', 's': '', 'n': 'خبز، لبن، أرز، زيت'},
  {'id': 'd2', 't': 'واي فاي البيت', 'u': '', 's': 'home2024', 'n': ''},
];

class VaultTab extends StatefulWidget {
  const VaultTab({super.key});
  @override
  State<VaultTab> createState() => _VaultTabState();
}

class _VaultTabState extends State<VaultTab>
    with AutomaticKeepAliveClientMixin<VaultTab> {
  final pw = TextEditingController();
  final pw2 = TextEditingController();
  Session? s;
  