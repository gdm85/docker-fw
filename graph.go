/*
 * docker-fw v0.2.0 - a complementary tool for Docker to manage custom
 *                    firewall rules between/towards Docker containers
 * Copyright (C) 2014 gdm85 - https://github.com/gdm85/docker-fw/

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
package main

import (
	"github.com/gdm85/go-dockerclient"
)

type Node struct {
	ingress int

	ID       string            // same as Container.ID
	Name     string            // used for debugging/dry-run purposes
	children SortableNodeArray // all direct one-way links (slice of container names)
}

type SortableNodeArray []*Node

func NewNode(container *docker.Container) *Node {
	return &Node{
		ID:       container.ID,
		Name:     container.Name[1:],
		children: SortableNodeArray{},
	}
}

func (node *Node) LinkTo(child *Node) {
	node.children = append(node.children, child)
	child.ingress++
}

///
/// 'a' node is 'less' than 'b' node if and only if:
///  - 'a' links to 'b'
///  - on any of the nodes visited by link paths starting from 'a', there is 'b',
///    or 'b' is in any of the link paths starting from any nodes visited in such link paths
///
/// nodes that have no incoming links (or already started nodes) have priority and go on top of the list
/// based on code by bjarneh - https://github.com/bjarneh/godag/blob/master/src/cmplr/dag.go
///
func (arr SortableNodeArray) TopSort() SortableNodeArray {
	zero := SortableNodeArray{}
	sorted := SortableNodeArray{}

	for _, v := range arr {
		if v.ingress == 0 {
			zero = append(zero, v)
		}
	}

	for len(zero) > 0 {

		node := zero[0]
		zero = zero[1:] // Pop

		for _, child := range node.children {
			child.ingress--
			if child.ingress == 0 {
				zero = append(zero, child)
			}
		}
		sorted = append(sorted, node)
	}

	if len(sorted) < len(arr) {
		panic("found cycle in DAG")
	}

	return sorted
}
