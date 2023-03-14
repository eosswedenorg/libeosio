/**
 * MIT License
 *
 * Copyright (c) 2019-2023 EOS Sw/eden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <chrono>
#include <libeosio/ec.hpp>
#include <libeosio/WIF.hpp>


std::chrono::duration<float> _run(size_t num_keys) {
	auto start = std::chrono::steady_clock::now();
	for(size_t i = 0; i < num_keys; i++) {
		struct libeosio::ec_keypair k;
		libeosio::ec_generate_key(&k);
	}
	return std::chrono::steady_clock::now() - start;
}

void test(size_t num_keys) {
	float t, kps;


	std::cout << "Running benchmark for " << num_keys << " keys" << std::endl;
	t = _run(num_keys).count();
	kps = static_cast<float>(num_keys) / t;

	std::cout << "Time: " << t << std::endl
		<< "KPS: " << kps << std::endl;
}

int main() {
	libeosio::ec_init();

	test(1000);
	test(10000);
	test(100000);

	libeosio::ec_shutdown();

	return 0;
}