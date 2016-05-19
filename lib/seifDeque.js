/** @file seifDeque.js
 *  @brief File containing the implementation of the double ended queue which
 *         is used in the protocol.
 *
 *  @author Aashish Sheshadri
 *  @author Rohit Harchandani
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2016 PayPal
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

/*jslint node: true */

function createDeque(func) {
    'use strict';

    let queue; // reference to the front of the deueue
    let tail; // reference to the back of the deqeue
    let queueSize = 0; // tracks size of the queue

    /**
     * @brief Inserts an item to the front of the deque.
     *
     * @param item is the object to be inserted.
     *
     */
    function insertFront(item) {
        let node = {item};
        if (queue === undefined) {
            queue = node;
            tail = node;
        } else {
            node.next = queue;
            queue.prev = node;
            queue = node;
        }
        queueSize = queueSize + 1;
    }

    /**
     * @brief Inserts an item to the back of the deque.
     *
     * @param item is the object to be inserted.
     *
     */
    function insertBack(item) {
        let node = {item};

        if (queue === undefined) {
            queue = node;
            tail = node;
        } else {
            tail.next = node;
            node.prev = tail;
            tail = node;
        }

        queueSize = queueSize + 1;
    }

    /**
     * @brief Removes an item from the front of the deque.
     *
     * @return object which was at the front of the deque.
     *
     */
    function removeFront() {
        if (queue === undefined) {
            return undefined;
        }

        let item = queue.item;
        queue = queue.next;

        if (queue !== undefined) {
            queue.prev = undefined;
        }

        queueSize = queueSize - 1;

        return item;
    }

    /**
     * @brief Removes an item from the back of the deque.
     *
     * @return object which was at the back of the deque.
     *
     */
    function removeBack() {
        if (queue === undefined) {
            return undefined;
        }

        let item = tail.item;
        tail = tail.prev;

        if (tail !== undefined) {
            tail.next = undefined;
        }

        return item;
    }

    /**
     * @brief Returns the current size of the deque.
     *
     * @return size of the deque.
     *
     */
    function size() {
        return queueSize;
    }

    /**
     * @brief Invokes the provided function on each item in the deque.
     *
     * @param forEachFunc is a function to be invoked on each item of the deque.
     *
     */
    function forEach(forEachFunc) {
        let it = queue;
        while (it !== undefined) {
            const item = it.item;
            forEachFunc(item);
            it = it.next;
        }
    }

    /**
     * @brief Invokes the stored function on the item at the front of the deque
     *        and removes it from the deque.
     *
     */
    function done() {
        let item = removeFront();
        if (item !== undefined) {
            if (func !== undefined && typeof func === "function") {
                func(item);
            }
        }
    }

    /**
     * @brief Clears the deque and resets its state.
     *
     */
    function clear() {
        queue = undefined;
        tail = undefined;
        queueSize = 0;
    }

    return Object.freeze({
        insertFront,
        insertBack,
        removeFront,
        removeBack,
        size,
        done,
        clear,
        forEach
    });
}


module.exports = createDeque;