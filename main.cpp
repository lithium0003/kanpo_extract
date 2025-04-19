#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <memory>

#include <openssl/evp.h>
#include <zlib.h>
#include <png.h>

class object {
    public:
        virtual ~object(){}
        virtual void print(int indent = 0) const {};
};

class null_object: public object {
    public:
        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << "null";
        }
};

class boolean_object: public object {
    private:
        bool _value;
    public:
        boolean_object(bool value) : _value(value) {}

        inline bool get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class integer_object: public object {
    private:
        int _value;
    public:
        integer_object(std::string value) {
            std::stringstream(value) >> _value;
        }

        inline int get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class real_object: public object {
    private:
        double _value;
    public:
        real_object(std::string value) {
            std::stringstream(value) >> _value;
        }

        inline double get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') <<_value;
        }
};

class string_object: public object {
    private:
        std::string _value;
    public:
        string_object(std::string value): _value(value) {}

        inline const std::string get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class name_object: public string_object {
    public:
        name_object(std::string value): string_object(value) {}
};

class array_object: public object {
    private:
        std::vector<std::shared_ptr<object>> _value;
    public:
        array_object(const std::vector<std::shared_ptr<object>> &value): _value(value) {}

        const std::shared_ptr<object> operator[](std::size_t idx) const {
            return _value[idx];
        }

        const size_t size() const {
            return _value.size();
        }

        void print(int indent = 0) const override {
            std::cout << std::endl;
            std::cout << std::string(indent + 1, ' ') << "[" << std::endl;
            for(auto &elem: _value) {
                elem->print(indent + 2);
                std::cout << std::endl;
            }
            std::cout << std::string(indent + 1, ' ') << "]";
        }
};

class dictionary_object: public object {
    private:
        std::map<std::string, std::shared_ptr<object>> _value;
        std::vector<std::string> _keys;
    public:
        dictionary_object(const std::vector<std::string> &keys, const std::map<std::string, std::shared_ptr<object>> &value)
            : _keys(keys), _value(value) {}

        const std::streamsize get_length() const {
            integer_object *length_value = dynamic_cast<integer_object*>(_value.at("Length").get());
            if(length_value != nullptr) {
                return length_value->get_value();
            }
            return -1;
        }

        const std::shared_ptr<object> operator[](const std::string key) const {
            return _value.at(key);
        }

        const bool isexists(const std::string key) const {
            return _value.count(key) == 1;
        }

        const std::vector<std::string>& get_keys() const {
            return _keys;
        }

        void merge(const dictionary_object &old) {
            for(const auto &key: old._keys) {
                if(isexists(key)) { 
                    continue;
                }
                _keys.push_back(key);
                _value[key] = old[key];
            }
        }

        void print(int indent = 0) const override {
            std::cout << std::endl;
            std::cout << std::string(indent + 1, ' ') << "<<" << std::endl;
            for(auto &elem: _keys) {
                std::cout << std::string(indent + 2, ' ') << elem << " : ";
                if(dynamic_cast<dictionary_object*>(_value.at(elem).get())) {
                    _value.at(elem)->print(indent + 2);
                }
                else if(dynamic_cast<array_object*>(_value.at(elem).get())) {
                    _value.at(elem)->print(indent + 2);
                }
                else {
                    _value.at(elem)->print();
                }
                std::cout << std::endl;
            }
            std::cout << std::string(indent + 1, ' ') << ">>" << std::endl;;
        }
};

class indirect_object: public object {
    private:
        int _object_number;
        int _generation_number;
        std::shared_ptr<object> _value;
    public:
        indirect_object(int object_number, int generation_number, std::shared_ptr<object> value)
            : _object_number(object_number), _generation_number(generation_number),
              _value(value) {}

        inline std::shared_ptr<object> get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _object_number << " " << _generation_number << " obj" << std::endl;
            _value->print(indent);
        }
};

class indirect_references_object: public object {
    private:
        int _object_number;
        int _generation_number;
    public:
        indirect_references_object(int object_number, int generation_number)
            : _object_number(object_number), _generation_number(generation_number) {}

        int get_object_number() const {
            return _object_number;
        }

        int get_generation_number() const {
            return _generation_number;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _object_number << " " << _generation_number << " R";
        }
};

class stream_object: public object {
    private:
        dictionary_object _dict;
        std::vector<uint8_t> _stream;

    public:
        stream_object(const dictionary_object &dict, const std::vector<uint8_t> &stream)
            : _dict(dict), _stream(stream) {}

        dictionary_object get_dict() const {
            return _dict;
        }

        std::vector<uint8_t> get_stream() const {
            return _stream;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << "stream: " << _stream.size() << " bytes" << std::endl;
            _dict.print(indent);
        }
};

bool is_whitespace(int c)
{
    return c == 0x00 || c == 0x09 || c == 0x0a || c == 0x0c || c == 0x0d || c == 0x20;
}

bool is_delimiter(int c)
{
    return c == 0x28 || c == 0x29 || c == 0x3c || c == 0x3e || c == 0x5b || c == 0x5d || c == 0x7b || c == 0x7d || c == 0x2f || c == 0x25;
}

bool is_end(int c)
{
    return is_whitespace(c) || is_delimiter(c);
}

std::shared_ptr<object> parse_object(std::istream &ss);

std::shared_ptr<object> parse_hexstring(std::istream &ss)
{
    std::string result = "";
    int c = 0;
    int v1 = -1;
    while(ss) {
        c = ss.get();
        if(c == '<') continue;
        if(c == '>') break;
        if(is_whitespace(c)) continue;
        int v;
        if(c >= '0' && c <= '9') {
            v = c - '0';
        }
        else if(c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        }
        else if(c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        }
        else {
            throw std::runtime_error("invalid hexstring");
        }
        if (v1 < 0) {
            v1 = v;
        }
        else {
            result += (v1 << 4) | v;
            v1 = -1;
        }
    }
    if(v1 >= 0) {
        result += (v1 << 4);
    }
    return std::shared_ptr<object>(new string_object(result));
}

std::shared_ptr<object> parse_literal(std::istream &ss)
{
    std::string result = "";
    bool isescape = false;
    bool isescapeCR = false;
    std::string octalstr = "";
    int nest = 0;
    while(ss) {
        char c = ss.get();
        if(!octalstr.empty() && c >= '0' && c <= '7') {
            octalstr += c;
            continue;
        }
        if(!octalstr.empty()) {
            int v = 0;
            for(auto o: octalstr) {
                int v2 = o - '0';
                v = (v << 3) | v2;
            }
            result += v;
            octalstr.clear();
        }
        if(isescape) {
            isescape = false;
            if(c == 'n') {
                c = 0x0a;
            }
            else if(c == 'r') {
                c = 0x0d;
            }
            else if(c == 't') {
                c = 0x09;
            }
            else if(c == 'b') {
                c = 0x08;
            }
            else if(c == 'f') {
                c = 0x0c;
            }
            else if(c == '(') {
                c = 0x28;
            }
            else if(c == ')') {
                c = 0x29;
            }
            else if(c == '\\') {
                c = 0x5c;
            }
            else if(c >= '0' && c <= '7') {
                octalstr += c;
            }
            else if(c == 0x0d) {
                c = 0x0a;
                if(ss.peek() == 0x0a) {
                    ss.get();
                }
            }
            else if(c == 0x0a) {
                c = 0x0a;
                if(ss.peek() == 0x0d) {
                    ss.get();
                }
            }
        }
        else if(c == '\\') {
            isescape = true;
            continue;
        }
        else if(c == '(') {
            if (nest == 0) {
                nest++;
                continue;
            }
            nest++;
        }
        else if(c == ')') {
            nest--;
            if (nest == 0) {
                break;
            }
        }
        result += c;
    }
    return std::shared_ptr<object>(new string_object(result));
}

std::shared_ptr<object> parse_name(std::istream &ss)
{
    char c = ss.get();
    while(c != '/') {
        c = ss.get();
    }
    std::string result = "";
    while(ss) {
        if(is_end(ss.peek())) break;
        c = ss.get();
        if(c < 0) break;
        if(c == '#') {
            c = ss.get();
            int v1;
            if(c >= '0' && c <= '9') {
                v1 = c - '0';
            }
            else if(c >= 'A' && c <= 'F') {
                v1 = c - 'A' + 10;
            }
            else if(c >= 'a' && c <= 'f') {
                v1 = c - 'a' + 10;
            }
            c = ss.get();
            int v2;
            if(c >= '0' && c <= '9') {
                v2 = c - '0';
            }
            else if(c >= 'A' && c <= 'F') {
                v2 = c - 'A' + 10;
            }
            else if(c >= 'a' && c <= 'f') {
                v2 = c - 'a' + 10;
            }
            result += (v1 << 4) | v2;
        }
        else {
            result += c;
        }
    }
    return std::shared_ptr<object>(new name_object(result));
}

std::shared_ptr<object> parse_array(std::stringstream &ss)
{
    ss.seekg(-1, std::ios::end);
    ss << ' ';
    ss.seekg(1, std::ios::beg);
    std::vector<std::shared_ptr<object>> arrayobj;
    while(ss) {
        if(is_whitespace(ss.peek())) {
            ss.get();
        }
        auto obj = parse_object(ss);
        if(obj) {
            arrayobj.push_back(obj);
        }
    }
    return std::shared_ptr<object>(new array_object(arrayobj));
}

std::shared_ptr<object> parse_dictionary(std::stringstream &ss)
{
    ss.seekg(-2, std::ios::end);
    ss << ' ';
    ss << ' ';
    ss.seekg(0, std::ios::beg);
    int count = 2;
    while(ss.get() != '<' || --count > 0);
    std::vector<std::string> keys;
    std::map<std::string, std::shared_ptr<object>> dictobj;
    while(ss) {
        std::shared_ptr<object> key = parse_object(ss);
        std::shared_ptr<object> value = parse_object(ss);
        if(key && value) {
            name_object *name_key = dynamic_cast<name_object*>(key.get());
            if(name_key != nullptr) {
                keys.push_back(name_key->get_value());
                dictobj[name_key->get_value()] = value;
            }
        }
    }
    return std::shared_ptr<object>(new dictionary_object(keys, dictobj));
}

std::shared_ptr<object> parse_indirectobject(std::istream &ss)
{
    std::string str1,str2;
    ss >> str1 >> str2;
    while(!is_end(ss.peek())) {
        ss.get();
    }

    int obj_num, gen_num;
    std::stringstream(str1) >> obj_num;
    std::stringstream(str2) >> gen_num;

    auto obj = parse_object(ss);
    if(!obj) throw std::runtime_error("parse error");

    std::string keyword;
    ss >> keyword;
    if(keyword == "stream") {
        if(ss.peek() == 0x0d) {
            ss.ignore(2);
        }
        else {
            ss.ignore();
        }
        std::vector<uint8_t> stream;
        keyword.clear();
        while(ss) {
            int c = ss.get();
            keyword += c;
            if(keyword.find("endstream") != std::string::npos) {
                for(auto k: keyword) {
                    stream.pop_back();
                }
                if(!stream.empty() && stream.back() == 0x0d) {
                    stream.pop_back();
                }
                break;
            }
            else if (keyword.size() > 9){
                keyword = keyword.substr(1);                
            }
            stream.push_back(c);
        }
        const dictionary_object *dict = dynamic_cast<const dictionary_object*>(obj.get());
        auto streamobj = std::shared_ptr<object>(new stream_object(*dict, stream));
        return std::shared_ptr<object>(new indirect_object(obj_num, gen_num, streamobj));
    }
    return std::shared_ptr<object>(new indirect_object(obj_num, gen_num, obj));
}

std::shared_ptr<object> parse_numeric(std::istream &is, std::istream &ss)
{
    std::string object1;
    is >> object1;
    auto pos1 = is.tellg();
    is.seekg(0, std::ios::end);
    ss.seekg(pos1 - is.tellg(), std::ios::cur);
    if(object1.find('.') == std::string::npos) {
        return std::shared_ptr<object>(new integer_object(object1));
    }
    else {
        return std::shared_ptr<object>(new real_object(object1));
    }
}

std::shared_ptr<object> parse_object(std::istream &ss)
{
    enum state {
        array,
        hexstring,
        dictionary,
        literalstring,
        name,
        escape,
        comment,
        stream,
        indirectobject,
        maybeobj,
        maybeobj2,
        maybeobj3,
        numeric
    };

    std::stringstream bs;
    std::vector<state> current_state;
    std::string keyword_buffer;

    while(ss) {
        char c0 = ss.peek();
        // std::cout << c0 << " " << (current_state.empty() ? -1 : current_state.back()) << std::endl;
        if (!current_state.empty() && current_state.back() == name && is_end(c0)) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_name(bs);
            }
        }
        else if (!current_state.empty() && current_state.back() == numeric && is_end(c0)) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && is_delimiter(c0)) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }

        char c = ss.get();
        // std::cout << c << " " << (current_state.empty() ? -1 : current_state.back()) << std::endl;
        bs << c;

        if (!current_state.empty() && current_state.back() == stream) {
            // std::cout << ss.tellg() << " " << keyword_buffer << std::endl;
            keyword_buffer += c;
            if(c == 'm' && keyword_buffer == "endstream") {
                keyword_buffer.clear();
                current_state.pop_back();
            }
            else if(keyword_buffer.size() >= 9) {
                keyword_buffer = keyword_buffer.substr(1);
            }
        }
        else if (!current_state.empty() && current_state.back() == escape) {
            current_state.pop_back();
        }
        else if (c == '\\') {
            keyword_buffer.clear();
            current_state.push_back(escape);            
        }
        else if (!current_state.empty() && current_state.back() == comment) {
            if(c == '\r') {
                if(ss.peek() == '\n') {
                    c = ss.get();
                    bs << c;
                }
                current_state.pop_back();
            }
            else if (c == '\n') {
                current_state.pop_back();
            }
        }
        else if (!current_state.empty() && current_state.back() == literalstring && c0 == ')') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_literal(bs);
            }                        
        }
        else if (!current_state.empty() && current_state.back() == literalstring) {
            // ignore spetials
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && is_whitespace(c)) {
            current_state.back() = maybeobj2;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && c == '.') {
            current_state.back() = numeric;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && std::string("0123456789").find_first_of(c) == std::string::npos) {
            current_state.pop_back();
        }
        else if (!current_state.empty() && current_state.back() == maybeobj2 && is_whitespace(c)) {
            current_state.back() = maybeobj3;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj2 && std::string("0123456789").find_first_of(c) == std::string::npos) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3 && c == 'R') {
            current_state.pop_back();
            std::string str1,str2,str3;
            std::stringstream(bs.str()) >> str1 >> str2 >> str3;

            int obj_num, gen_num;
            std::stringstream(str1) >> obj_num;
            std::stringstream(str2) >> gen_num;
            return std::shared_ptr<object>(new indirect_references_object(obj_num, gen_num));
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3 && c == 'o') {
            current_state.back() = indirectobject;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (c == '%') {
            keyword_buffer.clear();
            current_state.push_back(comment);
        }
        else if (c == '[') {
            keyword_buffer.clear();
            current_state.push_back(array);
        }
        else if (!current_state.empty() && current_state.back() == array && c == ']') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_array(bs);
            }
        }
        else if (!current_state.empty() && current_state.back() == hexstring && c == '<') {
            current_state.back() = dictionary;
        }
        else if (c == '<') {
            keyword_buffer.clear();
            current_state.push_back(hexstring);            
        }
        else if (!current_state.empty() && current_state.back() == hexstring && c == '>') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_hexstring(bs);
            }            
        }
        else if (!current_state.empty() && current_state.back() == dictionary && c == '>') {
            c = ss.get();
            bs << c;

            if(c == '>') {
                current_state.pop_back();
                if(current_state.empty()) {
                    return parse_dictionary(bs);
                }
            }
        }
        else if (c == '(') {
            keyword_buffer.clear();
            current_state.push_back(literalstring);            
        }
        else if (c == '/') {
            keyword_buffer.clear();
            current_state.push_back(name);            
        }
        else if (!current_state.empty() && current_state.back() == indirectobject) {
            if(!is_whitespace(c)) {
                keyword_buffer += c;
            }

            if(keyword_buffer == "endobj") {
                current_state.pop_back();
                return parse_indirectobject(bs);
            }
            if(keyword_buffer == "stream") {
                current_state.push_back(stream);
                keyword_buffer.clear();
            }
        }
        else if (current_state.empty()){
            if(!is_whitespace(c)) {
                keyword_buffer += c;
            }

            if(keyword_buffer == "null") {
                return std::shared_ptr<object>(new null_object());
            }
            if(keyword_buffer == "true") {
                return std::shared_ptr<object>(new boolean_object(true));
            }
            if(keyword_buffer == "false") {
                return std::shared_ptr<object>(new boolean_object(false));
            }

            if(c == '+' || c == '-') {
                current_state.push_back(numeric);
            }
            else if(std::string("0123456789").find_first_of(c) != std::string::npos) {
                current_state.push_back(maybeobj);
            }
        }
    }
    return std::shared_ptr<object>();
}

int check_header(std::ifstream &ifs)
{
    std::string header_buffer;
    std::getline(ifs, header_buffer);

    if(!header_buffer.empty() && header_buffer.back() == 13) {
        header_buffer = header_buffer.substr(0, header_buffer.size()-1);
    }

    if (header_buffer == "%PDF-1.0") {
        return 0;
    }
    if (header_buffer == "%PDF-1.1") {
        return 1;
    }
    if (header_buffer == "%PDF-1.2") {
        return 2;
    }
    if (header_buffer == "%PDF-1.3") {
        return 3;
    }
    if (header_buffer == "%PDF-1.4") {
        return 4;
    }
    if (header_buffer == "%PDF-1.5") {
        return 5;
    }
    if (header_buffer == "%PDF-1.6") {
        return 6;
    }
    if (header_buffer == "%PDF-1.7") {
        return 7;
    }
    if (header_buffer == "%PDF-2.0") {
        return 20;
    }
    std::cerr << header_buffer << std::endl;
    return -1;
}

std::streamoff get_startxref_pos(std::ifstream &ifs)
{
    ifs.seekg(-6, std::ios::end);
    std::string eofmarker_buffer;
    std::getline(ifs, eofmarker_buffer);
    if(eofmarker_buffer != "%%EOF") {
        return -1;
    }

    std::streamoff trailer_pos = 0;
    int lf_count = 0;
    while(lf_count < 3) {
        char c;
        trailer_pos--;
        ifs.seekg(trailer_pos, std::ios::end);
        ifs.get(c);
        if(c == 0x0a) {
            lf_count++;
        }
    }

    std::string trailer_buffer;
    std::getline(ifs, trailer_buffer);
    std::stringstream ss(trailer_buffer);
    std::streamoff startxref_pos;
    ss >> startxref_pos;
    return startxref_pos;
}

std::streamoff read_xref(std::ifstream &ifs, std::streamoff startxref_pos, std::map<int, std::streamoff> &cross_reference_table)
{
    ifs.seekg(startxref_pos, std::ios::beg);
    std::streamoff trailer_pos = -1;
    std::string table_header;
    std::getline(ifs, table_header);
    if(!table_header.empty() && table_header.back() == 13) {
        table_header = table_header.substr(0, table_header.size()-1);
    }
    if(table_header != "xref") {
        return -1;
    }
    std::getline(ifs, table_header);
    while(table_header.substr(0, 7) != "trailer") {
        std::stringstream ss(table_header);
        int start_object, number_object;
        ss >> start_object >> number_object;
        for(int i = 0; i < number_object; i++) {
            std::getline(ifs, table_header);
            std::streamoff offset;
            int generation;
            char inuse;
            std::stringstream ss(table_header);
            ss >> offset >> generation >> inuse;
            if(inuse == 'n') {
                if(cross_reference_table.count(start_object + i) == 0) {
                    cross_reference_table[start_object + i] = offset;
                }
            }
        }
        trailer_pos = ifs.tellg();
        std::getline(ifs, table_header);
    }
    return trailer_pos;
}

std::shared_ptr<object> read_trailer(std::ifstream &ifs, std::streamoff trailer_pos)
{
    ifs.seekg(trailer_pos, std::ios::beg);
    std::string trailer = "";
    std::string trailer_buffer = "";
    std::getline(ifs, trailer_buffer);
    trailer += trailer_buffer.substr(7) + '\n';
    std::getline(ifs, trailer_buffer);        
    while(trailer_buffer != "startxref") {
        trailer += trailer_buffer + '\n';
        std::getline(ifs, trailer_buffer);        
    }
    std::stringstream ss(trailer);
    return parse_object(ss);
}

std::shared_ptr<object> read_body(std::ifstream &ifs, std::streamoff pos)
{
    ifs.seekg(pos, std::ios::beg);
    return parse_object(ifs);
}

std::vector<uint8_t> hashlib(const char *alg, const std::vector<uint8_t> &message) 
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    std::vector<uint8_t> md_value(EVP_MAX_MD_SIZE, 0);
    unsigned int md_len, i;
    md = EVP_get_digestbyname(alg);
    mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
        printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return {};
    }
    if (!EVP_DigestUpdate(mdctx, message.data(), message.size())) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        return {};
    }
    if (!EVP_DigestFinal_ex(mdctx, md_value.data(), &md_len)) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return {};
    }
    EVP_MD_CTX_free(mdctx);
    md_value.resize(md_len);
    return md_value;
}

std::vector<uint8_t> do_crypt(int do_encrypt, const char *alg, bool padding, const uint8_t *key, const uint8_t *iv, const uint8_t *data, size_t data_size, int repeat = 1)
{
    std::vector<uint8_t> outbuf(data_size * repeat + EVP_MAX_BLOCK_LENGTH, 0);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, alg, NULL);
    if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL,
                            do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    if(!padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int output_len = 0;
    int outlen;
    for(int i = 0; i < repeat; i++) {
        if (!EVP_CipherUpdate(ctx, outbuf.data() + output_len, &outlen, data, data_size)) {
            /* Error */
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        output_len += outlen;
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf.data() + output_len, &outlen)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    output_len += outlen;
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    outbuf.resize(output_len);
    return outbuf;
}

std::vector<uint8_t> calculate_hash(int R, const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &udata)
{
    std::vector<uint8_t> str;
    std::copy(password.begin(), password.end(), std::back_inserter(str));
    std::copy(salt.begin(), salt.end(), std::back_inserter(str));
    std::copy(udata.begin(), udata.end(), std::back_inserter(str));
    auto k = hashlib("SHA256", str);
    if(R < 6) return k;
    int count = 0;
    while(true) {
        count++;
        std::vector<uint8_t> k1;
        std::copy(password.begin(), password.end(), std::back_inserter(k1));
        std::copy(k.begin(), k.end(), std::back_inserter(k1));
        std::copy(udata.begin(), udata.end(), std::back_inserter(k1));
        auto e = do_crypt(1, "aes-128-cbc", false, &k[0], &k[16], &k1[0], k1.size(), 64);
        int sum = 0;
        for(int i = 0; i < 16; i++) {
            sum += *(unsigned char *)&e.data()[i];
        }
        sum = sum % 3;
        if(sum == 0) {
            k = hashlib("SHA256", e);
        }
        else if(sum == 1) {
            k = hashlib("SHA384", e);
        }
        else {
            k = hashlib("SHA512", e);
        }
        int last_e = e.back();
        if((count >= 64) && (last_e <= count - 32)) {
            break;
        }
    }
    k.resize(32);
    return k;
}

std::vector<uint8_t> verify_owner_password(int R, std::vector<uint8_t> password, const std::vector<uint8_t> &o_value, const std::vector<uint8_t> &oe_value, const std::vector<uint8_t> &u_value)
{
    if(password.size() > 127) {
        password.resize(127);
    }
    std::vector<uint8_t> o_value0;
    std::copy(o_value.begin(), o_value.begin()+32, std::back_inserter(o_value0));
    std::vector<uint8_t> o_value32;
    std::copy(o_value.begin()+32, o_value.begin()+32+8, std::back_inserter(o_value32));
    std::vector<uint8_t> u_value48;
    std::copy(u_value.begin(), u_value.begin()+48, std::back_inserter(u_value48));
    if(calculate_hash(R, password, o_value32, u_value48) != o_value0) {
        return {};
    }
    std::vector<uint8_t> iv(16);
    std::vector<uint8_t> o_value40;
    std::copy(o_value.begin()+40, o_value.begin()+40+8, std::back_inserter(o_value40));
    auto tmp_key = calculate_hash(R, password, o_value40, u_value48);
    return do_crypt(0, "aes-256-cbc", false, &tmp_key[0], &iv[0], &oe_value[0], oe_value.size());
}

std::vector<uint8_t> verify_user_password(int R, std::vector<uint8_t> password, const std::vector<uint8_t> &u_value, const std::vector<uint8_t> &ue_value)
{
    if(password.size() > 127) {
        password.resize(127);
    }
    std::vector<uint8_t> u_value0;
    std::copy(u_value.begin(), u_value.begin()+32, std::back_inserter(u_value0));
    std::vector<uint8_t> u_value32;
    std::copy(u_value.begin()+32, u_value.begin()+32+8, std::back_inserter(u_value32));
    if(calculate_hash(R, password, u_value32, {}) != u_value0) {
        return {};
    }
    std::vector<uint8_t> iv(16);
    std::vector<uint8_t> u_value40;
    std::copy(u_value.begin()+40, u_value.begin()+40+8, std::back_inserter(u_value40));
    auto tmp_key = calculate_hash(R, password, u_value40, {});
    return do_crypt(0, "aes-256-cbc", false, &tmp_key[0], &iv[0], &ue_value[0], ue_value.size());
}

bool verify_perms(const std::vector<uint8_t> &key, const std::vector<uint8_t> &perms, int p, bool metadata_encrypted)
{
    std::vector<uint8_t> iv(16);
    auto p2 = do_crypt(0, "aes-256-ecb", false, &key[0], &iv[0], &perms[0], perms.size());
    std::vector<uint8_t> p1(p2.begin(), p2.begin()+4);
    p1.push_back(0xff);
    p1.push_back(0xff);
    p1.push_back(0xff);
    p1.push_back(0xff);
    if(metadata_encrypted) {
        p1.push_back('T');
    }
    else {
        p1.push_back('F');
    }
    p1.push_back('a');
    p1.push_back('d');
    p1.push_back('b');
    p2.resize(12);
    return p1 == p2;
}

std::vector<uint8_t> verify_v5(std::vector<uint8_t> password, int R, const std::vector<uint8_t> &O, const std::vector<uint8_t> &U, const std::vector<uint8_t> &OE, const std::vector<uint8_t> &UE)
{
    auto key = verify_owner_password(R, password, O, OE, U);
    if(key.empty()) {
        key = verify_user_password(R, password, U, UE);
    }
    return key;
}

const stream_object* get_stream_object(std::shared_ptr<object> base)
{
    const indirect_object *obj = dynamic_cast<const indirect_object*>(base.get());
    return dynamic_cast<const stream_object*>(obj->get_value().get());
}

const dictionary_object* get_dictonary_object(std::shared_ptr<object> base)
{
    const indirect_object *obj = dynamic_cast<const indirect_object*>(base.get());
    if(obj) {
        return dynamic_cast<const dictionary_object*>(obj->get_value().get());
    }
    return dynamic_cast<const dictionary_object*>(base.get());
}

const array_object* get_array(std::shared_ptr<object> base)
{
    return dynamic_cast<const array_object*>(base.get());
}

const dictionary_object* get_dictonary(std::shared_ptr<object> base)
{
    return dynamic_cast<const dictionary_object*>(base.get());
}

std::string get_string(std::shared_ptr<object> base)
{
    const string_object *s_ptr = dynamic_cast<const string_object*>(base.get());
    if(s_ptr) {
        return s_ptr->get_value();
    }
    else {
        return "";
    }
}

std::vector<uint8_t> get_bytes(std::shared_ptr<object> base)
{
    const string_object *s_ptr = dynamic_cast<const string_object*>(base.get());
    std::vector<uint8_t> result;
    if(s_ptr) {
        for(auto c: s_ptr->get_value()) {
            result.push_back((unsigned)c);
        }
    }
    return result;
}

int get_integer(std::shared_ptr<object> base)
{
    const integer_object *i_ptr = dynamic_cast<const integer_object*>(base.get());
    return i_ptr->get_value();
}

std::vector<uint8_t> ZlibInflate(std::vector<uint8_t> &data)
{
    constexpr auto BUFFER_SIZE = 0x4000;
    auto size = static_cast<unsigned int>(data.size());
    auto outBuf = new unsigned char[BUFFER_SIZE]();
    std::vector<uint8_t> outStream;
    z_stream zStream{ 0 };
    auto ret = inflateInit(&zStream);

    zStream.avail_in = size;
    zStream.next_in = data.data();
    do
    {
        zStream.next_out = outBuf;
        zStream.avail_out = BUFFER_SIZE;
        ret = inflate(&zStream, Z_NO_FLUSH);
        auto outSize = BUFFER_SIZE - zStream.avail_out;
        std::copy(outBuf, outBuf + outSize, std::back_inserter(outStream));
    } while (zStream.avail_out == 0);
    
    inflateEnd(&zStream);

    return outStream;
}

std::vector<uint8_t> process_filter(const std::string &filter, std::vector<uint8_t> &data)
{
    if(filter == "FlateDecode") {
        return ZlibInflate(data);
    }
    return data;
}

void save_as_png(const char *file_name, const uint8_t *data, int width, int height, int bit_depth, int rotate)
{
    auto png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if(!png_ptr) return;

    auto info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr)
    {
       png_destroy_write_struct(&png_ptr, NULL);
       return;
    }

    int w = width;
    int h = height;
    if(rotate == 90) {
        std::swap(w, h);
    }
    else if(rotate == 270) {
        std::swap(w, h);
    }

    png_bytepp rows = (png_bytepp)png_malloc(png_ptr, sizeof(png_bytep) * h);
    if(!rows) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return;
    }
    for(int y = 0; y < h; y++) {
        if ((rows[y] = (png_bytep)png_malloc(png_ptr, w)) == NULL) {
            for(int y2 = y-1; y2 >= 0; y2--) {
                png_free(png_ptr, rows[y2]);
            }
            png_free(png_ptr, rows);
            png_destroy_write_struct(&png_ptr, &info_ptr);
            return;    
        }
    }

    if(rotate == 0) {
        for(int y = 0; y < h; y++) {
            for(int x = 0; x < w; x++) {
                rows[y][x] = data[y * width + x];
            }
        }
    }
    else if(rotate == 90) {
        for(int y = 0; y < h; y++) {
            for(int x = 0; x < w; x++) {
                int x2 = w - x;
                int y2 = y;
                rows[y][x] = data[x2 * width + y2];
            }
        }
    }
    else if(rotate == 180) {
        for(int y = 0; y < h; y++) {
            for(int x = 0; x < w; x++) {
                int x2 = w - x;
                int y2 = h - y;
                rows[y][x] = data[y2 * width + x2];
            }
        }
    }
    else if(rotate == 270) {
        for(int y = 0; y < h; y++) {
            for(int x = 0; x < w; x++) {
                int x2 = x;
                int y2 = h - y;
                rows[y][x] = data[x2 * width + y2];
            }
        }
    }

    FILE *fp = fopen(file_name, "wb");
    if (!fp)
    {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return;
    }

    png_init_io(png_ptr, fp);

    png_set_IHDR(png_ptr, info_ptr, w, h, bit_depth, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    png_set_rows(png_ptr, info_ptr, rows);

    png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

    png_destroy_write_struct(&png_ptr, &info_ptr);

    fclose(fp);
}

class PDF_reader {
    private:
        std::string basename;
        std::ifstream ifs;
        std::map<int, std::streamoff> cross_reference_table;
        std::vector<uint8_t> file_encryption_key;

        std::shared_ptr<object> root_obj;
        std::shared_ptr<object> info_obj;
        std::shared_ptr<object> pages_obj;
        std::vector<std::shared_ptr<object>> page;

        std::shared_ptr<object> follow_reference(const std::shared_ptr<object> base) {
            const indirect_references_object *obj_ptr = dynamic_cast<const indirect_references_object*>(base.get());
            if(obj_ptr) {
                int obj_number = obj_ptr->get_object_number();
                std::cout << "object ref " << obj_number << std::endl;
                return read_body(ifs, cross_reference_table[obj_number]);    
            }
            return nullptr;
        }

        const dictionary_object* rootobj() {
            return get_dictonary_object(root_obj);
        }
        const dictionary_object* infoobj() {
            return get_dictonary_object(info_obj);
        }
        const dictionary_object* pagesobj() {
            return get_dictonary_object(pages_obj);
        }

        const std::vector<uint8_t> get_stream(const stream_object* stream_obj)
        {
            auto dict = stream_obj->get_dict();
            std::string filter = "";

            if (dict.isexists("Filter")) {
                filter = get_string(dict["Filter"]);
            }

            auto stream = stream_obj->get_stream();
            if(file_encryption_key.empty()) return process_filter(filter, stream);

            auto value = do_crypt(0, "aes-256-cbc", true, file_encryption_key.data(), &stream[0], &stream[16], stream.size() - 16);
            return process_filter(filter, value);
        }

    public:
        PDF_reader(std::string filename)
            : basename(filename), ifs(filename, std::ios::binary) 
        {
            auto pos = basename.find_last_of('.');
            if(pos >= 0) {
                basename.erase(basename.begin()+pos, basename.end());
            }
            if(!ifs) {
                std::cerr << "failed to open file: " << filename << std::endl;
                throw std::runtime_error("file open error");
            }

            int pdf_ver = check_header(ifs);
            if(pdf_ver < 0) {
                std::cerr << "invalid pdf header." << std::endl;
                throw std::runtime_error("header error");
            }

            std::streamoff startxref_pos = get_startxref_pos(ifs);
            if(startxref_pos < 0) {
                std::cerr << "invalid eof marker." << std::endl;
                throw std::runtime_error("footer error");
            }

            std::streamoff trailer_pos = read_xref(ifs, startxref_pos, cross_reference_table);
            if(trailer_pos < 0) {
                std::cerr << "invalid xref." << std::endl;
                throw std::runtime_error("xref error");
            }

            std::shared_ptr<object> trailer = read_trailer(ifs, trailer_pos);
            dictionary_object *trailer_dict = dynamic_cast<dictionary_object*>(trailer.get());
            if(trailer_dict == nullptr) {
                throw std::runtime_error("trailer error");
            }
            // trailer_dict->print();

            if(trailer_dict->isexists("Prev")) {
                std::streamoff prev_offset = get_integer((*trailer_dict)["Prev"]);
                while(true) {
                    std::streamoff trailer_pos = read_xref(ifs, prev_offset, cross_reference_table);
                    if(trailer_pos < 0) {
                        std::cerr << "invalid xref." << std::endl;
                        throw std::runtime_error("xref error");
                    }
    
                    std::shared_ptr<object> trailer2 = read_trailer(ifs, trailer_pos);
                    dictionary_object *trailer_dict2 = dynamic_cast<dictionary_object*>(trailer2.get());
                    if(trailer_dict2 == nullptr) {
                        throw std::runtime_error("trailer error");
                    }
                    trailer_dict->merge(*trailer_dict2);
                    // trailer_dict2->print();
                    if(trailer_dict2->isexists("Prev")) {
                        prev_offset = get_integer((*trailer_dict2)["Prev"]);
                    }
                    else {
                        break;
                    }
                }
            }
            // trailer_dict->print();

            int table_size = get_integer((*trailer_dict)["Size"]);
            std::cout << table_size << std::endl;
            std::vector<int> ignore_index;
            for(const auto &elem: cross_reference_table) {
                if(elem.first >= table_size) {
                    ignore_index.push_back(elem.first);
                }
            }
            for(const auto &key: ignore_index) {
                cross_reference_table.erase(key);
            }

            if(trailer_dict->isexists("Encrypt")) {
                auto encrypt_obj = follow_reference((*trailer_dict)["Encrypt"]);
                auto encrypt = get_dictonary_object(encrypt_obj);

                auto O = get_bytes((*encrypt)["O"]);
                auto U = get_bytes((*encrypt)["U"]);
                auto OE = get_bytes((*encrypt)["OE"]);
                auto UE = get_bytes((*encrypt)["UE"]);
                auto Perms = get_bytes((*encrypt)["Perms"]);
                auto P = get_integer((*encrypt)["P"]);
                auto R = get_integer((*encrypt)["R"]);
                auto V = get_integer((*encrypt)["V"]);
                auto LengthBit = get_integer((*encrypt)["Length"]);

                // std::cout << "R : " << R << std::endl;
                // std::cout << "V : " << V << std::endl;

                // std::cout << "O : ";
                // for(const auto c: O) {
                //     std::cout << std::hex << (int)c << " ";
                // }
                // std::cout << std::endl;
                // std::cout << std::dec << O.size() << std::endl;

                // std::cout << "U : ";
                // for(const auto c: U) {
                //     std::cout << std::hex << (int)c << " ";
                // }
                // std::cout << std::endl;
                // std::cout << std::dec << U.size() << std::endl;

                // std::cout << "OE : ";
                // for(const auto c: OE) {
                //     std::cout << std::hex << (int)c << " ";
                // }
                // std::cout << std::endl;
                // std::cout << std::dec << OE.size() << std::endl;

                // std::cout << "UE : ";
                // for(const auto c: UE) {
                //     std::cout << std::hex << (int)c << " ";
                // }
                // std::cout << std::endl;
                // std::cout << std::dec << UE.size() << std::endl;

                file_encryption_key = verify_v5({}, R, O, U, OE, UE);
                
                // std::cout << "file_encryption_key : ";
                // for(auto c: file_encryption_key) {
                //     std::cout << std::hex << (int)c << " ";
                // }
                // std::cout << std::endl;
                // std::cout << std::dec << file_encryption_key.size() << std::endl;

                std::cout << "verify: " << verify_perms(file_encryption_key, Perms, P, true) << std::endl;
            }
            root_obj = follow_reference((*trailer_dict)["Root"]);
            info_obj = follow_reference((*trailer_dict)["Info"]);
            pages_obj = follow_reference((*rootobj())["Pages"]);
            pages_obj->print();

            auto pagecount = get_integer((*pagesobj())["Count"]);
            std::cout << pagecount << " pages" << std::endl;
            auto pagekids_ptr = get_array((*pagesobj())["Kids"]);
            std::vector<std::shared_ptr<object>> tmppage;
            for(int i = 0; i < pagekids_ptr->size(); i++) {
                auto page_obj = follow_reference((*pagekids_ptr)[i]);
                tmppage.push_back(page_obj);
            }
            for(int i = 0; i < tmppage.size(); i++) {
                // tmppage[i]->print();
                auto dict = get_dictonary_object(tmppage[i]);
                if(!dict) continue;
                if(dict->isexists("Kids")) {
                    auto pagekids_ptr = get_array((*dict)["Kids"]);
                    for(int j = 0; j < pagekids_ptr->size(); j++) {
                        auto page_obj = follow_reference((*pagekids_ptr)[j]);
                        // page_obj->print();
                        tmppage.push_back(page_obj);
                    }
                }
            }
            for(int i = 0; i < tmppage.size(); i++) {
                auto dict = get_dictonary_object(tmppage[i]);
                if(!dict) continue;
                if(dict->isexists("Kids")) continue;
                page.push_back(tmppage[i]);
            }
        }

        void extract_pages(int page_count = 0) {
            for(const auto &p: page) {
                page_count++;
                std::cout << "page: " << page_count << std::endl;
                auto dict = get_dictonary_object(p);
                dict->print();
                int rotate = 0;
                if(dict->isexists("Rotate")) {
                    rotate = get_integer((*dict)["Rotate"]);
                }
                if(dict->isexists("Resources")) {
                    auto tmp_resources = follow_reference((*dict)["Resources"]);
                    auto resources = get_dictonary_object(tmp_resources ? tmp_resources : (*dict)["Resources"]);
                    resources->print();
                    if(resources->isexists("XObject")) {
                        auto xobject = get_dictonary((*resources)["XObject"]);
                        std::string key = "Im0";
                        if(xobject->isexists(key)) {
                            auto Im0 = follow_reference((*xobject)[key]);
                            Im0->print();
                            auto image_stream = get_stream_object(Im0);
                            auto im_dict = image_stream->get_dict();
                            auto width = get_integer(im_dict["Width"]);
                            auto height = get_integer(im_dict["Height"]);
                            auto bitDepth = get_integer(im_dict["BitsPerComponent"]);
                            std::stringstream ss;
                            ss << basename << "-page" << std::setfill('0') << std::setw(4) << page_count << ".png";
                            auto stream = get_stream(image_stream);
                            if(std::find_if(stream.begin(), stream.end(), [](uint8_t x) { return x < 255; }) != stream.end()) {
                                save_as_png(ss.str().c_str(), stream.data(), width, height, bitDepth, rotate);
                            }
                        }
                    }    
                }
            }
        }
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "usage: " << argv[0] << " input.pdf (start_page_no)" << std::endl;
        return 0;
    }
    auto pdf = PDF_reader(argv[1]);
    int start_page = 0;
    if (argc >= 3) {
        std::stringstream(argv[2]) >> start_page; 
    }

    pdf.extract_pages(start_page);

    return 0;
}