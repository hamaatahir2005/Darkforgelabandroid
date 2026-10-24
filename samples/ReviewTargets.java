// Synthetic review targets only. NOT Android vulnerabilities and never executed.
class ReviewTargets {
    void permission(Context context) {
        context.checkCallingPermission("lab.permission.ADMIN");
        privilegedAction(); // synthetic missing enforcement
    }
    Object deserialize(ObjectInputStream stream) { return stream.readObject(); }
    int parse(String untrusted) { return Integer.parseInt(untrusted); }
    void log(String token) { Log.d("LAB", "token=" + token); }
}
